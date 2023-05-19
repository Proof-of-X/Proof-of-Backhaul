/*
    Copyright (c) 2023 kaleidoscope-blockchain

    Unless specified otherwise, this work is licensed under the Creative Commons
    Attribution-NonCommercial 4.0 International License.

    To view a copy of this license, visit:
        http://creativecommons.org/licenses/by-nc/4.0/

    ----------------------------------------------------------------------------

    Licenses for the following files/packages may have different licenses:

    1. `font.dart`

        Big by Glenn Chappell 4/93 -- based on Standard
        Includes ISO Latin-1
        Greek characters by Bruce Jakeway <pbjakeway@neumann.uwaterloo.ca>
        figlet release 2.2 -- November 1996
        Permission is hereby given to modify this font, as long as the
        modifier's name is placed on a comment line.

    2. Dart packages used in this software have the following licenses:
        BSD-3-Clause    (https://opensource.org/license/bsd-3-clause/)
        MIT             (https://opensource.org/license/mit/)
*/

import "dart:io";
import "dart:convert";

import "../common/log.dart";
import "../common/utils.dart";
import "../common/abc.dart"                                     as abc;

import "constants.dart";
import "pol.dart"                                               as pol;

class Client extends pol.Client
{
    Client (final Map args) : super ("challenger", args)
    {
        // nothing
    }

    @override
    Future<bool> init () async
    {
        init_done   = await super.init();
        log         = LOG("Challenger.Client", set_client : this);

        return init_done;
    }

    @override
    Future<void> run () async
    {
        if (! init_done)
            await init();

        await super.run();
    }

    @override
    Future<Map> handle_websocket (final Map m) async
    {
        if (in_a_challenge)
        {
            log.error("already in a challenge");
            return {};
        }

        in_a_challenge                  = true;

        assert (m["message"]            is Map);
        assert (m["signature"]          == null);

        final Map ci = m["message"]; // challenge-info

        assert(ci["challenge_id"]                    is String);
        assert(ci["challenge_start_time"]            is String);
        assert(ci["challenge_timeout"]               is String);

        assert(m["message_type"]                     == "pol_challenge_for_challenger");
        assert(ci["prover"]                          is Map);

        final challenge_handler = ChallengeHandler (ci, crypto, this);
        await challenge_handler.init();

        final challenge_start_time      = DateTime
                                            .parse(ci["challenge_start_time"])
                                            .toUtc()
                                            .microsecondsSinceEpoch;

        final now                       = Now(ntp_offset)
                                            .microsecondsSinceEpoch;

        if (challenge_start_time > now)
        {
            final int diff          = challenge_start_time - now;
            final int wait_time     = (diff / 1000000).ceil();

            final wait = Duration (seconds : wait_time - 10);

            if (wait.inSeconds > 0)
            {
                log.info("Waiting for ${wait_time-10} seconds");
                await Future<void>.delayed(wait);
            }

            log.success("Ready for challenge");
        }

        final challenge_timeout = DateTime
                                        .parse(ci["challenge_timeout"])
                                        .toUtc()
                                        .microsecondsSinceEpoch;

        final current_time      = Now(ntp_offset)
                                        .microsecondsSinceEpoch;

        final timeout_in_microseconds = challenge_timeout - current_time;

        log.important('Timeout : ${timeout_in_microseconds ~/ 1000000} seconds');

        Future.delayed (Duration(microseconds : timeout_in_microseconds), () async
        {
            await report_challenge_results  (challenge_handler);
            await challenge_handler.cleanup ("Timeout");
        });

        await challenge_handler.run();

        return challenge_handler.challenge_result;
    }

    @override
    Future<void> report_challenge_results (final abc.ChallengeHandler ch) async
    {
        if (ch.sent_challenge_results)
            return;

        final message = jsonEncode ({
            "type"  : "challenge_result",
            "data"  : {
                "challenge_id"  : ch.challenge_info["challenge_id"],
                "timestamp"     : Now(ntp_offset).toString(),
                "result"        : ch.challenge_result
            }
        });

       await crypto
            .sign(message)
            .then
        (
            (final String signature) async
            {
                final signed_message = {
                    "message"     : message,
                    "keyType"     : crypto.keyType,
                    "publicKey"   : crypto.publicKey,
                    "signature"   : signature,
                };

                log.important("Latency : ${ch.challenge_result['latency']}");

                Map r = await do_post (CHALLENGE_RESULT_URL,signed_message);

                if (r["result"] == null)
                    log.error("Could not sent Results");
                else
                {
                    if (r["result"]["success"] == true)
                    {
                        ch.sent_challenge_results = true;
                        log.success("Sent Results");
                    }
                    else
                    {
                        log.error("Could not sent Results");
                    }
                }
            }
        );
    }
}

class ChallengeHandler extends pol.ChallengeHandler
{
    late Map    prover;

    final Map <String,bool> got_udp_pong = {};

    ChallengeHandler
    (
        final Map           _challenge_info,
        final abc.Crypto    _crypto,
        final pol.Client    _client,
        {
            InternetAddress?    setSourceAddress4   = null,
            InternetAddress?    setSourceAddress6   = null,
            int                 setSourcePort       = 0
        }
    ) : super
    (
            "challenger",
            _challenge_info,
            _crypto,
            setSourceAddress4   : setSourceAddress4,
            setSourceAddress6   : setSourceAddress6,
            setSourcePort       : setSourcePort
    )
    {
        client              = _client;
        log                 = LOG("Challenger.ChallengeHandler");

        prover              = challenge_info["prover"];
        prover["udp_port"]  = PROVER_PORT;

        final IPv6          = prover["IPv6"];

        if (IPv6 != null)
        {
            if (IPv6.startsWith("::ffff:") && IPv6.contains("."))
            {
                prover["IPv4"] = IPv6.split("::ffff:")[1];
                prover["IPv6"] = null;
            }
        }

        prover["ip"] = InternetAddress (
            prover["IPv6"] ?? prover["IPv4"]
        );

        if (prover["ip"].type == InternetAddressType.IPv6)
            is_IPv6_challenge = true;

        whitelist                       = [ prover ];

        challenge_result["latitude"]    = 0.0;
        challenge_result["longitude"]   = 0.0;
        challenge_result["city"]        = "unknown";
        challenge_result["region"]      = "unknown";
        challenge_result["country"]     = "unknown";
    }

    @override
    Future<bool> init () async
    {
        init_done = await super.init();

        return init_done;
    }

    @override
    Future<bool> run () async
    {
        if (! init_done)
            await init();

        try
        {
            log.important("1/2 START send_udp_ping");

            if (await send_UDP_ping())
            {
                log.success     ("1/2 DONE send_UDP_ping");
                log.important   ("2/2 START receive_UDP_pong");

                if (await receive_UDP_pong())
                {
                    log.success("2/2 DONE  receive_UDP_pong");

                    challenge_succeeded = true;
                }
            }
        }
        catch (e)
        {
            log.error("Exception in RUN: $e");
        }

        await client.report_challenge_results(this);

        return challenge_succeeded;
    }

    Future<bool> send_UDP_ping () async
    {
        /// wait for `udp_connect` from prover with private IP

        bool got_udp_connect = false;

        if (challenge_info["prover"]["has_public_IP"] == false)
        {
            final Map udp_connect = await get_UDP_message (
                            ["udp_connect"],
                            timeout_in_milliseconds : 1000,
                            is_IPv6_challenge       : is_IPv6_challenge
            );

            final cpk = udp_connect["publicKey"];

            if (cpk != null && udp_connect["SOURCE_PORT"] != null)
            {
                if (prover["publicKey"] == cpk)
                {
                    got_udp_connect     = true;
                    prover["udp_port"]  = udp_connect["SOURCE_PORT"];
                }
            }
        }

        final udp_ping = jsonEncode ({
            "type" : "udp_ping",
            "data" : {
                "challenge_id"      : challenge_info ["challenge_id"],
                "timestamp"         : Now(ntp_offset).toString(),
                "source_port"       : source_port,
            }
        });

        final signed_udp_ping = {
            "message"     : udp_ping,
            "keyType"     : crypto.keyType,
            "publicKey"   : crypto.publicKey,
            "signature"   : await crypto.sign(udp_ping),
        };

        if (challenge_info["prover"]["has_public_IP"] == false)
        {
            if (got_udp_connect == false)
                return false;
        }

        return send_UDP_message (prover, "udp_ping", signed_udp_ping);
    }

    Future<bool> receive_UDP_pong() async
    {
        /// wait for `udp_pong` from prover

        final timeout = Now(ntp_offset).add (
                Duration (milliseconds : 10000) // 10 seconds
        ).microsecondsSinceEpoch;

        while (true)
        {
            final Map udp_pong  = await get_UDP_message (
                                ["udp_pong"],
                                timeout_in_milliseconds : 1000,
                                is_IPv6_challenge       : is_IPv6_challenge
            );

            if (udp_pong["DATA"] != null)
            {
                final cpk = udp_pong["publicKey"];

                if (cpk != null)
                {
                    log.success("Got udp_pong from : $cpk");
                    return true;
                }
            }

            final now = Now(ntp_offset).microsecondsSinceEpoch;

            if (now > timeout)
                return false;
        }
    }
}

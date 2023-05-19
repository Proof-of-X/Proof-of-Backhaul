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

import "pol.dart"                                               as pol;


class Client extends pol.Client
{
    Client (final Map args) : super ("prover", args)
    {
        // nothing
    }

    @override
    Future<bool> init () async
    {
        init_done   = await super.init();
        log         = LOG("Prover.Client", set_client : this);

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

        assert(m["message_type"]                     == "pol_challenge_for_prover");
        assert(ci["challengers"]                     is List);

        final challenge_handler = ChallengeHandler (ci, crypto, this);
        await challenge_handler.init();

        log.info("Number of challengers : ${ci['challengers'].length}");

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

        ch.sent_challenge_results = true;
    }
}

class ChallengeHandler extends pol.ChallengeHandler
{
    late List               challengers;

    final Map <String,bool>         got_udp_ping      = {};

    int num_challengers_with_private_IPs              = 0;

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
            "prover",
            _challenge_info,
            _crypto,
            setSourceAddress4   : setSourceAddress4,
            setSourceAddress6   : setSourceAddress6,
            setSourcePort       : setSourcePort
    )
    {
        client              = _client;
        log                 = LOG("Prover.ChallengeHandler");

        challengers         = challenge_info["challengers"];

        for (int i = 0; i < challengers.length; ++i)
        {
            final cpk           = challengers[i]["publicKey"];
            got_udp_ping [cpk]  = false;

            final IPv6          = challengers[i]["IPv6"];

            if (challengers[i]["has_public_IP"] == false)
                ++num_challengers_with_private_IPs;

            if (IPv6 != null)
            {
                if (IPv6.startsWith("::ffff:") && IPv6.contains("."))
                {
                    challengers[i]["IPv4"] = IPv6.split("::ffff:")[1];
                    challengers[i]["IPv6"] = null;
                }
            }

            challengers[i]["ip"] = InternetAddress (
                challengers[i]["IPv6"] ?? challengers[i]["IPv4"]
            );

            if (challengers[i]["ip"].type == InternetAddressType.IPv6)
                is_IPv6_challenge = true;
        }

        whitelist = challengers;
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

        bool challenge_succeeded = false;

        try
        {
            if (await send_UDP_connect())
            {
                log.important ("1/ START receive_UDP_ping    ...");

                if (await receive_UDP_ping ())
                {
                    log.success     ("1/2 DONE  receive_UDP_ping ...");
                    log.important   ("2/2 START send_UDP_pong    ...");

                    if (await send_UDP_pong())
                    {
                        log.important("2/2 DONE send_UDP_pong    ...");
                        challenge_succeeded = true;
                    }
                }
            }
        }
        catch (e) {}

       return challenge_succeeded;
    }

    Future<bool> receive_UDP_ping () async
    {
        int num_udp_pings_received = 0;

        final String?   challenge_timeout = challenge_info["challenge_timeout"];

        if (challenge_timeout == null)
            return false;
 
        final challenge_end_time = DateTime
                                    .parse(challenge_timeout)
                                    .toUtc()
                                    .microsecondsSinceEpoch;

        while (num_udp_pings_received < challengers.length)
        {
            final now = Now(ntp_offset).microsecondsSinceEpoch;

            if (now > challenge_end_time)
            {
                log.error("Timeout - received udp_pings : $num_udp_pings_received/${challengers.length}");
                return false;
            }

            final Map udp_ping = await get_UDP_message (
                            ["udp_ping"],
                            is_IPv6_challenge   : is_IPv6_challenge
            );

            final cpk = udp_ping["publicKey"];

            if (cpk != null && udp_ping["SOURCE_PORT"] != null)
            {
                if (got_udp_ping[cpk] == false)
                {
                    got_udp_ping[cpk] = true;

                    ++num_udp_pings_received;

                    for (int i = 0; i < challengers.length; ++i)
                    {
                        if (challengers[i]["publicKey"] == cpk)
                        {
                            challengers[i]["udp_port"] = udp_ping["SOURCE_PORT"];

                            break;
                        }
                    }
                }
            }
        }

        return true;
    }

    Future<bool> send_UDP_pong () async
    {
        final udp_pong = jsonEncode ({
            "type" : "udp_pong",
            "data" : {
                "challenge_id"      : challenge_info ["challenge_id"],
                "timestamp"         : Now(ntp_offset).toString(),
                "source_port"       : source_port,
            }
        });

        final signed_udp_pong = {
            "message"     : udp_pong,
            "keyType"     : crypto.keyType,
            "publicKey"   : crypto.publicKey,
            "signature"   : await crypto.sign(udp_pong),
        };

        for (final Map c in challengers)
        {
            // ignore challengers with public ip and who did not send udp_ping

            final cpk = c["publicKey"];

            if (c["has_public_IP"] == false && got_udp_ping [cpk] == false)
                continue;

            await send_UDP_message (c, "udp_pong", signed_udp_pong);
        }

        return init_done;
    }

    Future<bool> send_UDP_connect () async
    {
        // if prover is behind NAT, send udp_connect

        if (challenge_info["has_public_IP"] == false)
        {
            log.important("0/2 START send_UDP_connect");

            final udp_connect = jsonEncode ({
                "type" : "udp_connect",
                "data" : {
                    "challenge_id"      : challenge_info ["challenge_id"],
                    "timestamp"         : Now(ntp_offset).toString()
                }
            });

            final signed_udp_connect = {
                "message"     : udp_connect,
                "keyType"     : crypto.keyType,
                "publicKey"   : crypto.publicKey,
                "signature"   : await crypto.sign(udp_connect)
            };

            for (final Map c in challengers)
            {
                send_UDP_message (c, "udp_connect", signed_udp_connect);
            }

            log.success("0/2 DONE send_UDP_connect");
        }

        return true;
    }
}

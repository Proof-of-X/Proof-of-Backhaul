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
import "dart:typed_data";

import "../common/log.dart";
import "../common/utils.dart";
import "../common/abc.dart"                                     as abc;

import "constants.dart";
import "../common/constants.dart";

import "pob.dart"                                               as pob;

import "package:bit_array/bit_array.dart";

class Client extends pob.Client
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
        assert(ci["total_num_packets_for_challenge"] is int);

        assert(m["message_type"]                     == "pob_challenge_for_prover");
        assert(ci["challengers"]                     is List);

        assert(ci["max_packets_per_challenger"]      is int);

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

class ChallengeHandler extends pob.ChallengeHandler
{
    final Map <String,BitArray>     packet_bitmap     = {};
    final Map <String,int>          challenger_hash   = {};

    late List                       challengers;

    final Map <String,bool>         got_udp_pong      = {};

    int num_challengers_with_private_IPs              = 0;

    int hash_of_hashes  = 0;
    int uplink_rate     = 0; // Uplink backhaul of prover

    ChallengeHandler
    (
        final Map           _challenge_info,
        final abc.Crypto    _crypto,
        final pob.Client    _client,
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
            got_udp_pong [cpk]  = false;

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

        if (challenge_info["has_public_IP"] == true)
        {
            await start_websocket_server();
        }
        else
        {
            final List awaits = [];

            for (final Map c in challengers)
            {
                awaits.add (
                    start_websocket_client (c["ip"].address, c["publicKey"])
                );
            }

            for (final a in awaits)
            {
                await a;
            }
        }

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
            log.important("1/7 START send_udp_ping");

            if (await send_udp_ping())
            {
                log.success     ("1/7 DONE  send_udp_ping");
                log.important   ("2/7 START receive_udp_pong");

                if (await receive_udp_pong())
                {
                    log.success     ("2/7 DONE  receive_udp_pong");
                    log.important   ("3/7 START send_challenge_initiate_message");

                    if (await send_challenge_initiate_message())
                    {
                        log.success     ("3/7 DONE  send_challenge_initiate_message");
                        log.important   ("4/7 START received_enough_packets_for_challenge");

                        String result = await received_enough_packets_for_challenge();

                        log.success("4/7 DONE  $result : received_enough_packets_for_challenge");

                        if (result == "OK")
                        {
                            log.important("5/7 START send_hash_AND_hash_of_hashes");

                            if (await send_hash_AND_hash_of_hashes())
                            {
                                log.success     ("5/7 DONE  send_hash_AND_hash_of_hashes");
                                log.important   ("6/7 START send_all_hashes_AND_packet_bitmap");

                                if (await send_all_hashes_AND_packet_bitmap())
                                {
                                    log.success     ("6/7 DONE  send_all_hashes_AND_packet_bitmap");
                                    log.important   ("7/7 START send_end_challenge");

                                    challenge_succeeded = true;

                                    if (await send_end_challenge())
                                    {
                                        log.success("7/7 DONE  send_end_challenge");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (e)
        {
            log.error("Exception in RUN : $e");
            // XXX print exception
        }

        if (! challenge_succeeded)
        {
            // XXX print error
            log.error("Challenge failed");
        }

        await cleanup("Done Challenge");

        return challenge_succeeded;
    }

    Future<void> runUplink() async {
        bool challenge_succeeded = false;
        try {
            if (sent_all_packets_for_challenge_uplink()) {
                // XXX wait for ack ?
                challenge_succeeded = true;
            }
        } catch (e) {
            // XXX print exception
        }

        if (!challenge_succeeded) {
            // XXX print error
        }

        socket.close();

        return;
    }

    bool sent_all_packets_for_challenge_uplink() {
        int pktTxTime                   = (((UDP_CHUNK_SIZE + UDP_HEADER_SIZE) * 8) / uplink_rate).round() *
                                            challengers.length;
        int curTime                     = Now(ntp_offset).microsecondsSinceEpoch;
        int nextTime                    = curTime;
        int max_packets_per_challenger  = challenge_info["max_packets_per_challenger"];
        final s                         = StringBuffer();
        s.write('0' * (UDP_CHUNK_SIZE - 'message'.length));
        final message                   = {'message': s.toString()};
        while (max_packets_per_challenger > 0) {
            nextTime += pktTxTime;
            for (final c in challengers) {
                send_message(c, "uplink_packets", message);
            }
            max_packets_per_challenger--;
            curTime = Now(ntp_offset)
                            .microsecondsSinceEpoch;

            while (curTime < nextTime) {
                curTime = Now(ntp_offset).microsecondsSinceEpoch;
            }
        }

        return true;
    }

    Future<String> received_enough_packets_for_challenge() async
    {
        final int?              max_packets_per_challenger      = challenge_info["max_packets_per_challenger"];
        final int?              total_num_packets_for_challenge = challenge_info["total_num_packets_for_challenge"];
        final String?           challenge_timeout               = challenge_info["challenge_timeout"];

        if (max_packets_per_challenger == null)
            return "max_packets_per_challenger is null";

        if (total_num_packets_for_challenge == null)
            return "total_num_packets_for_challenge is null";

        if (challenge_timeout == null)
            return "challenge_timeout is null";

        final challenge_end_time = DateTime
                                    .parse(challenge_timeout)
                                    .toUtc()
                                    .microsecondsSinceEpoch;

        int num_packets_received = 0;

        while (num_packets_received < total_num_packets_for_challenge)
        {
            final now = Now(ntp_offset).microsecondsSinceEpoch;

            if (now > challenge_end_time)
            {
                log.error("Timeout - received : $num_packets_received/$total_num_packets_for_challenge");
                return "Timed Out";
            }

            final Map signed_message = await get_UDP_message (
                        ["challenge_packet"],
                        verifySignature         : false,
                        processMessageFunction  : process_challenge_packet,
                        is_IPv6_challenge       : is_IPv6_challenge
            );

            final String? cpk = signed_message["publicKey"]; // challenger's publicKey

            if (cpk == null)
                continue;

            final int?      random_number     = signed_message["random_number"];
            final int?      sequence_number   = signed_message["sequence_number"];

            // invalid data
            if (sequence_number == null || random_number == null || sequence_number >= max_packets_per_challenger)
                continue;

            // invalid cpk : "did not send udp_pong" -OR- already received this message
            if (packet_bitmap[cpk] == null || packet_bitmap[cpk]![sequence_number] == true)
                continue;

            final int? ch = challenger_hash[cpk];

            // invalid cpk
            if (ch == null)
                continue;

            // increment num packets after everything looks right

            packet_bitmap   [cpk]?.setBit(sequence_number);
            challenger_hash [cpk] = ch ^ random_number;

            ++num_packets_received;
        }

        return "OK";
    }

    Future<bool> send_udp_ping () async
    {
        /// wait for `udp_connect` from challengers with private IP

        final Map got_udp_connect = {};

        for (int i = 1; i <= num_challengers_with_private_IPs; ++i)
        {
            final Map udp_connect = await get_UDP_message (
                            ["udp_connect"],
                            timeout_in_milliseconds : 1000,
                            is_IPv6_challenge       : is_IPv6_challenge
            );

            final cpk = udp_connect["publicKey"];

            if (cpk != null && udp_connect["SOURCE_PORT"] != null)
            {
                got_udp_connect[cpk] = true;

                for (int i = 0; i < challengers.length; ++i)
                {
                    if (challengers[i]["publicKey"] == cpk)
                    {
                        challengers[i]["udp_port"] = udp_connect["SOURCE_PORT"];
                        break;
                    }
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

        for (final Map c in challengers)
        {
            // ignore challengers with public ip and who did not send udp_connect

            final cpk = c["publicKey"];

            if (c["has_public_IP"] == false && got_udp_connect[cpk] == false)
                continue;

            await send_UDP_message (c, "udp_ping", signed_udp_ping);
        }

        return true;
    }

    Future<bool> receive_udp_pong() async
    {
        /// wait for `udp_pong` from all challengers

        int num_udp_pongs_received = 0;

        final timeout = Now(ntp_offset).add (
                Duration (milliseconds : 10000) // 10 seconds
        ).microsecondsSinceEpoch;

        while (num_udp_pongs_received < challengers.length)
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
                    if (got_udp_pong[cpk] == false)
                    {
                        got_udp_pong    [cpk]   = true;
                        challenger_hash [cpk]   = 0;
                        packet_bitmap   [cpk]   = BitArray (challenge_info["max_packets_per_challenger"]);

                        ++num_udp_pongs_received;

                        log.success("Got udp_pong from : $cpk");
                    }
                }
            }

            final now = Now(ntp_offset).microsecondsSinceEpoch;

            if (now > timeout)
                break;
        }

        // TODO XXX recalulate rate of packets here : to be sent to /start-challenge

        return (num_udp_pongs_received == challengers.length);
    }

    Future<bool> send_challenge_initiate_message () async
    {
        const message_type = "start_challenge";

        final message = jsonEncode ({
            "type" : message_type,
            "data" : {
                "challenge_id"      : challenge_info ["challenge_id"],
                "challenge_port"    : source_port,
                "timestamp"         : Now(ntp_offset).toString()
            }
        });

        final   Map got_result      = {};
                Map signed_message  = {};

        await crypto
            .sign(message)
            .then
        (
                (final String signature) async
                {
                    signed_message = {
                        "message"     : message,
                        "keyType"     : crypto.keyType,
                        "publicKey"   : crypto.publicKey,
                        "signature"   : signature,
                    };

                    for (final Map c in challengers)
                    {
                        final cpk = c["publicKey"];

                        // send message only if this challenger responded to our udp_ping

                        if (got_udp_pong[cpk] == true)
                            got_result[cpk] = await send_message (c, message_type, signed_message);
                    }
                }
        );

        // try 5 more times, if we failed to send message

        bool got_forbidden = false;

        for (int i = 1; i <= 5; ++i)
        {
            got_forbidden = false;

            for (final Map c in challengers)
            {
                final cpk = c["publicKey"];

                if (got_udp_pong[cpk] == true)
                {
                    if (got_result[cpk] == false)
                    {
                        log.info("Retrying $i time for $cpk");

                        got_result[cpk] = await send_message (c, message_type,  signed_message );

                        if (got_result[cpk] == false)
                            got_forbidden = true;
                    }
                }
            }

            if (got_forbidden == false)
                return true;
        }

        return false;
    }

    Future<bool> send_hash_AND_hash_of_hashes () async
    {
        calculate_hash_of_hashes();

        const message_type              = "hash_AND_hash_of_hashes";
        final unsigned_hash_of_hashes   = hash_of_hashes.toUnsigned(HASH_SIZE_IN_BITS);

        for (final c in challengers)
        {
            final cpk = c["publicKey"];

            if (got_udp_pong[cpk] == false)
                continue;

            final message   = jsonEncode ({
                "type"  : message_type,
                "data"  : {
                    "challenge_id"      : challenge_info["challenge_id"],
                    "timestamp"         : Now(ntp_offset).toString(),
                    "hash"              : challenger_hash[cpk]?.toUnsigned (HASH_SIZE_IN_BITS),
                    "hash_of_hashes"    : unsigned_hash_of_hashes,
                    "num_packets"       : packet_bitmap[cpk]?.cardinality,
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

                     await send_message (c, message_type, signed_message);
                }
            );
        }

        return true;
    }

    Future<bool> send_all_hashes_AND_packet_bitmap () async
    {
        return (await send_all_hashes() && await send_packet_bitmap());
    }

    Future<bool> send_all_hashes() async
    {
        const message_type = "all_hashes";

        final message = jsonEncode ({
            "type"  : message_type,
            "data"  : {
                "challenge_id"  : challenge_info["challenge_id"],
                "timestamp"     : Now(ntp_offset).toString(),
                "all_hashes"    : challenger_hash.values.toList(),
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

                    for (final Map c in challengers)
                    {
                        final cpk = c["publicKey"];

                        if (got_udp_pong[cpk] == true)
                            await send_message (c, message_type, signed_message);
                    }
              }
        );

        return true;
    }

    Future<bool> send_packet_bitmap () async
    {
        const message_type = "packet_bitmap";

        for (final c in challengers)
        {
            String cpk = c["publicKey"];

            if (got_udp_pong[cpk] == false)
                continue;

            String? bitmap = packet_bitmap[cpk]?.toBinaryString();

            if (bitmap == null)
                continue;

            String compressed_bitmap    = jsonEncode (
                                            gzip.encode (bitmap.codeUnits)
                                        );

            final message = jsonEncode ({
                "type"  : message_type,
                "data"  : {
                    "challenge_id"  : challenge_info["challenge_id"],
                    "timestamp"     : Now(ntp_offset).toString(),
                    "packet_bitmap" : compressed_bitmap
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

                        await send_message (c, message_type, signed_message);
                    }
               );
        }

        return true;
    }

    Future<bool> send_end_challenge() async
    {
        const message_type = "end_challenge";

        final message = jsonEncode ({
                "type"  : message_type,
                "data"  : {
                    "challenge_id"  : challenge_info["challenge_id"],
                    "timestamp"     : Now(ntp_offset).toString()
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

                for (final c in challengers)
                {
                    final cpk = c["publicKey"];

                    if (got_udp_pong[cpk] == true)
                        await send_message (c, message_type, signed_message);
                }
            }
        );

        return true;
    }

    void calculate_hash_of_hashes ()
    {
        hash_of_hashes = 0;

        for (final ch in challenger_hash.values)
        {
            hash_of_hashes ^= ch;
        }
    }

    @override
    Future<void> handle_challenge_message (final String string_signed_message, final InternetAddress ip, final WebSocket ws) async
    {
        if (string_signed_message[0] != "{") // expecting a JSON
            return;

        bool            is_sender_IPv6    = ip.type == InternetAddressType.IPv6;
        final           clean_address     = process_ip (ip.address);
        String          ip_version        = is_sender_IPv6 ? "IPv6" : "IPv4";

        if (ip_version == "IPv6" && ip.address != clean_address)
        {
            ip_version      = "IPv4";
            is_sender_IPv6  = false;
        }

        final List<int> sender_ip = is_sender_IPv6?
                                    Uri.parseIPv6Address(clean_address):
                                    Uri.parseIPv4Address(clean_address);

        final Map signed_message  = await process_message_as_json (
                                        string_signed_message,
                                        sender_ip,
                                        ip_version,
                                        0       // ignore sender port for TCP
                                  );

        if (signed_message["message"] == null)
            return;

        Map message = {};

        try
        {
            message = jsonDecode(signed_message["message"]);
        }
        catch (e)
        {
            ws_log.error("Invalid signed_message : $e");
            return ws.close();
        }

        final cpk = signed_message["publicKey"];

        if (cpk == null)
        {
            ws_log.error("Got invalid message : $signed_message -> $message");
            return ws.close();
        }

        challenge_websocket [cpk] = ws;
    }

    /*
    * This function process received challenge message as raw bytes,
    * since jsonDecode was taking more time.
    */

    Future<Map> process_challenge_packet (final Uint8List message) async
    {
        final Map m = {
            "publicKey"         : "",
            "signature"         : "",
            "sequence_number"   : 0,
            "random_number"     : 0,
        };

        if (message.length == UDP_CHUNK_SIZE && message[0] == MESSAGE_TYPE_CHALLENGE_PACKET)
        {
            for (int i = 0; i < challenge_id_in_ascii.length; ++i)
            {
                if (challenge_id_in_ascii[i] != message [INDEX_START_CHALLENGE_ID + i])
                    return m; // reject invalid challenge id
            }

            m["sequence_number"] =  message [INDEX_START_SEQUENCE_NUMBER + 0]       |
                                    message [INDEX_START_SEQUENCE_NUMBER + 1] <<  8 |
                                    message [INDEX_START_SEQUENCE_NUMBER + 2] << 16 |
                                    message [INDEX_START_SEQUENCE_NUMBER + 3] << 24 ;

            m["random_number"]   =  message [INDEX_START_RANDOM_NUMBER   + 0]       |
                                    message [INDEX_START_RANDOM_NUMBER   + 1] <<  8 |
                                    message [INDEX_START_RANDOM_NUMBER   + 2] << 16 |
                                    message [INDEX_START_RANDOM_NUMBER   + 3] << 24 ;

            final keyLength                     = message [INDEX_START_PUBLIC_KEY_LENGTH];
            final INDEX_END_PUBLIC_KEY          = INDEX_START_PUBLIC_KEY + keyLength - 1;
            final INDEX_START_SIGNATURE_LENGTH  = INDEX_END_PUBLIC_KEY + 1;

            m["publicKey"] = ascii.decode (
                                Uint8List.sublistView (
                                    message,
                                    INDEX_START_PUBLIC_KEY,
                                    INDEX_END_PUBLIC_KEY + 1
                                )
            );

            if (message[INDEX_START_SIGNATURE_LENGTH] > 0)
            {
                // verify signature
            }
            else
            {
                // XXX sender did not send any signature
            }
        }

        return m;
    }
}

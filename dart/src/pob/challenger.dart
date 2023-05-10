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
import "../common/crypto-factory.dart"                          as cryptoFactory;

import 'package:dart_ping/dart_ping.dart';

import 'package:enough_ascii_art/enough_ascii_art.dart'         as art;
import "../common/font.dart"                                    as font;

class Client extends pob.Client
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
        assert(ci["total_num_packets_for_challenge"] is int);

        assert(m["message_type"]                     == "pob_challenge_for_challenger");
        assert(ci["prover"]                          is Map);

        assert(ci["max_packets_per_challenger"]      is int);

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

class ChallengeHandler extends pob.ChallengeHandler
{
    final Map   sent_random_number                  = {};

    List        received_all_hashes                 = [];

    int?        received_hash                       = null;
    int?        received_hash_of_hashes             = null;
    String?     received_packet_bitmap              = null;

    int         number_of_packets_received          = 0;

    late Map    prover;

    final Map<int,List<int>> challenge_packets      = {};

    bool        bandwidth_calculated                = false;

    final Map<String,String> allowed_message_types  = new Map.from (ALL_VALID_CHALLENGE_STATES_FOR_CHALLENGER);

    bool all_hashes_received    = false;
    bool packet_bitmap_received = false;

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

        challenge_result["latency"]     = 50.0;
        challenge_result["bandwidth"]   = 0.0;
    }

    @override
    Future<bool> init () async
    {
        init_done = await super.init();

        if (init_done)
        {
            init_done = false;

            await calculate_median_latency();
            await generate_challenge_packets();

            if (challenge_info["prover"]["has_public_IP"] == false)
            {
                await start_websocket_server();
            }
            else
            {
                await start_websocket_client (
                    prover["ip"].address,
                    prover["publicKey"]
                );
            }

            init_done = true;
        }

        return init_done;
    }

    Future<void> process_UDP_ping (final Map data) async
    {
        if (data["SOURCE_PORT"] is int && data["SOURCE_PORT"] > 0)
        {
            prover["udp_port"] = data["SOURCE_PORT"];
            await send_UDP_pong();
        }
        else
        {
            log.error("Got invalid message : $data");
        }
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

        await send_UDP_message (prover, "udp_pong", signed_udp_pong);

        return init_done;
    }

    @override
    Future<bool> run () async
    {
        if (! init_done)
            await init();

        if (challenge_info["has_public_IP"] == false)
        {
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

            send_UDP_message (prover, "udp_connect", signed_udp_connect);
        }

        log.important("Waiting for udp ping ...");

        final Map udp_ping = await get_UDP_message (
                            ["udp_ping"],
                            is_IPv6_challenge : is_IPv6_challenge
        );

        process_UDP_ping (udp_ping);

        return true;
    }

    void calculate_bandwidth()
    {
        log.important("Time taken : ${end_time-start_time}");

        if (bandwidth_calculated == false && start_time != -1 && end_time != -1)
        {
            final time_in_seconds   = (end_time - start_time) / 1000000.0;

            final num_bits          = challenge_info["total_num_packets_for_challenge"]
                                            *
                                      (UDP_CHUNK_SIZE + UDP_HEADER_SIZE) * 8.0;

            final double bandwidth  = num_bits/time_in_seconds;

            log.important("Bandwidth : $num_bits/$time_in_seconds = ${bandwidth}");

            challenge_result["bandwidth"]                   = bandwidth;
            challenge_result["start_time"]                  = start_time;
            challenge_result["end_time"]                    = end_time;
            challenge_result["number_of_packets_received"]  = end_time;

            bandwidth_calculated = true;
        }
    }

    Future<Map> runUplink() async {
        Map result                  = {};
        bool challenge_succeeded    = false;

        try {
            result = receive_enough_challenge_packets_uplink();
        } catch (e) {
            // XXX print exception
        }

        if (!challenge_succeeded) {
            // XXX print error
        }

        socket4.close();
        socket6.close();

        return result;
    }

    Map receive_enough_challenge_packets_uplink() {
        int num_packets_to_rx   = challenge_info["num_packets"];
        bool first              = true;
        int start_time          = 0;
        while (num_packets_to_rx > 0) {
            Datagram? d = socket4.receive();
            if (d != null) {
                if (d.data.length < UDP_CHUNK_SIZE) {
                    return {}; // received smaller than expected size packet
                }
                if (first) {
                    start_time = Now(ntp_offset).millisecondsSinceEpoch;
                    first = false;
                }
                num_packets_to_rx--;
            }
        }
        int end_time    = Now(ntp_offset).millisecondsSinceEpoch;

        double BW       = (challenge_info["num_packets"] *
                            (UDP_CHUNK_SIZE + UDP_HEADER_SIZE) * 8) /
                            ((end_time - start_time) * 1000); // BW in Mbps;
        Map result      = {"start_time": start_time, "end_time": end_time, "BW": BW};
        return result;
    }

    Future<void> generate_challenge_packets () async
    {
        log.info("Generating challenge packets ...");

        if (Platform.isAndroid || Platform.isIOS)
        {
            await generate_UNSIGNED_challenge_packets ();
        }
        else
        {
            await generate_UNSIGNED_challenge_packets ();
        }

        log.important("Done generating challenge packets!");
    }

    Future<void> generate_SIGNED_challenge_packets () async
    {
        final String    challenge_id                = challenge_info["challenge_id"];
        final int       max_packets_per_challenger  = challenge_info["max_packets_per_challenger"] ?? 0;

        for (int seq = 0; seq < max_packets_per_challenger; ++seq)
        {
            final random_number = RNG
                                    .nextInt    (MAX_HASH)
                                    .toUnsigned (HASH_SIZE_IN_BITS);

            final bytes_builder = BytesBuilder();
            // message_type = 0 -> for challenge_packets
            bytes_builder.add([0]);
            bytes_builder.add(int8bytes(utf8.encode(challenge_id).length));
            // add challenge_id - 127 bytes
            bytes_builder.add(utf8.encode(challenge_id));
            // add seq and random_number
            bytes_builder.add(int32bytes(seq));
            bytes_builder.add(int32bytes(random_number));

            String message = String.fromCharCodes(bytes_builder.toBytes());

            await crypto
                .sign(message)
                .then
            (
                (final String signature)
                {
                    int keyType = 0; // 0 for solana, 1 for filetype
                    if (crypto.keyType == "solana")
                        keyType = 0;
                    else
                        keyType = 1;
                    bytes_builder.add(int8bytes(keyType));
                    // add public key and signature
                    bytes_builder.add(int8bytes(utf8.encode(crypto.publicKey).length)); // one byte key length
                    bytes_builder.add(utf8.encode(crypto.publicKey));
                    bytes_builder.add(int8bytes(utf8.encode(signature).length)); // one byte signature length
                    bytes_builder.add(utf8.encode(signature));

                    final padding_required = UDP_CHUNK_SIZE - bytes_builder.toBytes().length;

                    if (padding_required > 0)
                        bytes_builder.add(utf8.encode("0" * padding_required));

                    challenge_packets   [seq]    = bytes_builder.toBytes();
                    sent_random_number  [seq]    = random_number;
                }
            );
        }
    }

    Future<void> generate_UNSIGNED_challenge_packets () async
    {
        final           public_key_in_ascii         = ascii.encode(crypto.publicKey);

        final int       max_packets_per_challenger  = challenge_info["max_packets_per_challenger"] ?? 0;

        final keyType   = cryptoFactory.CRYPTO_KEY_TYPE [crypto.keyType] ?? 0;
        final keyLength = crypto.publicKey.length;

        final INDEX_END_PUBLIC_KEY                  = INDEX_START_PUBLIC_KEY + keyLength - 1;
        final INDEX_START_SIGNATURE_LENGTH          = INDEX_END_PUBLIC_KEY + 1;

        for (int seq = 0; seq < max_packets_per_challenger; ++seq)
        {
            final random_number = RNG
                                    .nextInt    (MAX_HASH)
                                    .toUnsigned (HASH_SIZE_IN_BITS);

            final message   = Uint8List (UDP_CHUNK_SIZE);

            message[0]      = MESSAGE_TYPE_CHALLENGE_PACKET;
            message[1]      = CHALLENGE_ID_LENGTH;

            for (int i = INDEX_START_CHALLENGE_ID; i <= INDEX_END_CHALLENGE_ID; ++i) {
                message[i]  = challenge_id_in_ascii [i - INDEX_START_CHALLENGE_ID];
            }

            message [INDEX_START_SEQUENCE_NUMBER + 0]   = (seq & 0x000000FF);
            message [INDEX_START_SEQUENCE_NUMBER + 1]   = (seq & 0x0000FF00) >>  8;
            message [INDEX_START_SEQUENCE_NUMBER + 2]   = (seq & 0x00FF0000) >> 16;
            message [INDEX_START_SEQUENCE_NUMBER + 3]   = (seq & 0xFF000000) >> 24;

            message [INDEX_START_RANDOM_NUMBER   + 0]   = (random_number & 0x000000FF);
            message [INDEX_START_RANDOM_NUMBER   + 1]   = (random_number & 0x0000FF00) >>  8;
            message [INDEX_START_RANDOM_NUMBER   + 2]   = (random_number & 0x00FF0000) >> 16;
            message [INDEX_START_RANDOM_NUMBER   + 3]   = (random_number & 0xFF000000) >> 24;

            message [INDEX_START_PUBLIC_KEY_TYPE]       = keyType;
            message [INDEX_START_PUBLIC_KEY_LENGTH]     = keyLength;

            for (int i = INDEX_START_PUBLIC_KEY; i <= INDEX_END_PUBLIC_KEY; ++i) {
                message[i]  = public_key_in_ascii [i - INDEX_START_PUBLIC_KEY];
            }

            message [INDEX_START_SIGNATURE_LENGTH] = 0;

            challenge_packets   [seq]    = message;
            sent_random_number  [seq]    = random_number;
        }
    }

    bool process_challenge_initiate_message (final Map data)
    {
        if (data["challenge_port"] is int)
        {
           // our destination port is the sender's source port
           destination_port = data["challenge_port"];
        }

        final challenge_start_time      = DateTime
                                            .parse(challenge_info["challenge_start_time"])
                                            .toUtc()
                                            .microsecondsSinceEpoch;

        final now                       = Now(ntp_offset)
                                            .microsecondsSinceEpoch;

        final int wait_microseconds = ((challenge_start_time - challenge_result["latency"]/2.0) - now).toInt();

        final wait = Duration (microseconds : wait_microseconds);

        if (wait_microseconds > 0)
            sleep(wait);

        send_challenge_packets();

        return true;
    }

    Stream<int> getSequenceNumbers (final int max_packets_per_challenger) async*
    {
        // XXX yield (i + 1000000000);
        for (int i = 0; i < max_packets_per_challenger; ++i)
        {
            yield i;
        }
    }

    Future<bool> send_challenge_packets () async
    {
        const message_type = "challenge_packet";

        final int max_packets_per_challenger  = challenge_info["max_packets_per_challenger"] ?? 0;

        int nextTime = 0;

        final wait_duration = ((UDP_CHUNK_SIZE + UDP_HEADER_SIZE) * 8.0) ~/challenge_info["rate_of_packets_mbps"];

        if (challenge_packets[0] != null)
        {
            send_UDP_message_bytes (prover, message_type, challenge_packets[0] ?? EMPTY_PACKET);

            final double n = challenge_result["latency"] ?? 0.0;

            final now = Now(ntp_offset).microsecondsSinceEpoch;

            start_time = now + (n ~/ 2.0);
            nextTime  = now + wait_duration;

            challenge_result["start_time"] = start_time;

            log.important('Sent first packet @ ${Now(ntp_offset)}');
        }

        bool got_hash_packet = false;

        // 0th packet has already been sent
        for (int i = 1; i < max_packets_per_challenger; ++i)
        {
            //print("==> Start ${Now(ntp_offset)}");
            final now = Now(ntp_offset).microsecondsSinceEpoch;

            final int sleep_time = ((nextTime - now) > 0) ? (nextTime - now) : 0;

            if (sleep_time > 0)
                sleep(Duration(microseconds: sleep_time));

            nextTime += wait_duration;

            send_UDP_message_bytes (prover, message_type, challenge_packets[i] ?? EMPTY_PACKET);

            //print("==> After encode ${Now(ntp_offset).microsecondsSinceEpoch - prevTime};");

            //log.info("Sent $i message to $prover from ${socket4.port}");

            Datagram? datagram = null;
            String ip_version  = "IPv6";

            if (is_IPv6_challenge)
            {
                datagram = socket6.receive();
            }
            else
            {
                datagram    = socket4.receive();
                ip_version  = "IPv4";
            }

            if (datagram == null || datagram.data.length == 0 || datagram.data.length > UDP_CHUNK_SIZE)
            {
                continue;
            }

            last_message_received_time = Now(ntp_offset); /// update the last packet time

            final sender_address    = datagram.address.address;
            final clean_address     = process_ip (sender_address);

            if (ip_version == "IPv6" && sender_address != clean_address)
            {
                ip_version = "IPv4";
            }

            final sender_ip = (ip_version == "IPv6") ?
                                    Uri.parseIPv6Address(clean_address):
                                    Uri.parseIPv4Address(clean_address);

            try
            {
                final String string_signed_message = String.fromCharCodes(datagram.data);

                final verifySignature   = (Platform.isAndroid || Platform.isIOS) == true ? false : true; // don't verify signatures on Phones
                final signed_message    = await process_message_as_json (string_signed_message, sender_ip, ip_version, datagram.port, verifySignature : verifySignature);

                if (signed_message["message"] != null)
                {
                    Map m = jsonDecode(signed_message["message"]);

                    if (m["type"] == "hash_AND_hash_of_hashes")
                    {
                        if (process_hash_AND_hash_of_hashes (signed_message["DATA"]))
                        {
                            got_hash_packet = true;
                            return true;
                        }
                    }
                }
            }
            catch (e)
            {
                log.error("GOT exception $e");
                continue;
            }
        }

        log.info("Sent all packets : ${challenge_packets.length}");

        if (! got_hash_packet)
        {
            final Map r = await get_UDP_message (
                ["hash_AND_hash_of_hashes"],
                is_IPv6_challenge : is_IPv6_challenge
            );

            if (r["DATA"] != null)
            {
                return process_hash_AND_hash_of_hashes (r["DATA"]);
            }
        }

        return false;
    }

    bool process_hash_AND_hash_of_hashes (final Map data)
    {
        double n = challenge_result["latency"] ?? 0.0;

        end_time = last_message_received_time.microsecondsSinceEpoch - (n ~/ 2.0);

        received_hash               = data["hash"];           // must be verified when we get packet_bitmap
        received_hash_of_hashes     = data["hash_of_hashes"];

        if (received_hash == null || received_hash_of_hashes == null)
            return false;

        return true;
    }

    Future<bool> process_all_hashes(final Map data) async
    {
        received_all_hashes = data["all_hashes"];

        return true;
    }

    Future<bool> process_packet_bitmap (final Map data) async
    {
        List<int> compressed_bitmap = [];

        try
        {
            compressed_bitmap = jsonDecode (data["packet_bitmap"]).cast<int>();
        }
        catch(e)
        {
            log.error("Invalid 'packet_bitmap' : $e");
            return false;
        }

        received_packet_bitmap = String.fromCharCodes (
                                    gzip.decode (compressed_bitmap)
                               );

        if (received_packet_bitmap == null || received_packet_bitmap == "")
            return false;

        int calculated_hash = 0;

        int bitmap_length = received_packet_bitmap?.length ?? 0;

        for (int i = 0; i < bitmap_length; ++i)
        {
            if (received_packet_bitmap?[i] == "1")
            {
                ++number_of_packets_received;
                calculated_hash = calculated_hash ^ sent_random_number[i];
            }
        }

        final unsigned_caclulated_hash = calculated_hash
                                            .toUnsigned (HASH_SIZE_IN_BITS);


        if (received_hash == unsigned_caclulated_hash)
        {
            challenge_succeeded = true;
            log.success("Challenge Succeeded");
        }
        else
        {
            challenge_succeeded = false;
            log.error("Challenge Failed");
            await client.report_challenge_results(this);
        }

        return challenge_succeeded;
    }

    Future<double> calculate_median_latency () async
    {
        const double default_latency_value = 35.0;  // use apt default latency based on setup

        // ping -c 10 -i 1 prover

        final ping = Ping(prover["ip"].address, count:5, interval:1, encoding : Utf8Codec(allowMalformed: true));

        List<double> latencyArray = [];

        log.info("Sending ping");

        await for (final p in ping.stream)
        {
            if (p.response != null)
            {
                if (p.response?.time == null)
                    log.error("*");
                else
                {
                    if (p.response?.time?.inMicroseconds == null)
                    {
                        log.warning("*");
                        continue;
                    }

                    log.success("*");

                    int? lat = p.response?.time?.inMicroseconds;

                    if (lat != null)
                        latencyArray.add (lat/1000.0);
                }
            }
        }

        if (latencyArray.length == 0) {
            return default_latency_value;
        }

        latencyArray.sort();

        double latency = 0.0;

        int mid = (latencyArray.length ~/ 2);

        // median of latencies

        if (latencyArray.length % 2 == 0)
        {
            latency = (latencyArray[mid] + latencyArray[mid + 1])/2.0;
        }
        else
        {
            latency = latencyArray[mid];
        }

        challenge_result["latency"] = latency;

        return latency;
    }

    @override
    Future<void> handle_challenge_message (final String string_signed_message, final InternetAddress ip, final WebSocket ws) async
    {
        if (string_signed_message == "ping" || string_signed_message == "pong")
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

        final received_message_type = message["type"];
        final amt                   = allowed_message_types [challenge_state];

        if (received_message_type == "websocket_connect")
            return;

        if (amt == null || received_message_type == null || received_message_type != amt)
        {
            ws_log.error("Got invalid message type : $received_message_type for $challenge_state");
            return ws.close();
        }

        // the sender can no longer send this message
        allowed_message_types.remove(challenge_state);
        challenge_state = amt;

        final Map data = signed_message["DATA"];

        ws_log.success("Got $received_message_type");

        if (message["type"] == "start_challenge" && prover["udp_port"] == 0)
        {
            log.info("error!");
            return ws.add('{"error":"Please send `udp_ping` first"}');
        }

        ws.add("ok");

        switch (message["type"])
        {
                    case "start_challenge":
                    {
                        process_challenge_initiate_message (data);
                        break;
                    }

                    case "all_hashes":
                    {
                        await process_all_hashes (data);

                        all_hashes_received = true;

                        if (packet_bitmap_received == true)
                        {
                            calculate_bandwidth();

                            await client.report_challenge_results(this);

                            final result = art.renderFiglet((challenge_result["bandwidth"] / 1000000).toStringAsFixed(5) + "Mbps", art.Font.text(font.text));
                            print(result);
                        }

                        break;
                    }

                    case "packet_bitmap":
                    {
                        await process_packet_bitmap (data);

                        packet_bitmap_received = true;

                        if (all_hashes_received == true)
                        {
                            calculate_bandwidth();

                            await client.report_challenge_results(this);

                            final result = art.renderFiglet((challenge_result["bandwidth"] / 1000000).toStringAsFixed(5) + "Mbps", art.Font.text(font.text));
                            print(result);
                        }

                        break;
                    }

                    case "end_challenge":
                    {
                        await cleanup("End Challenge");
                        break;
                    }
                }
    }

    @override
    Future<void> cleanup (final String from) async
    {
        if (cleanup_done)
            return;

        log.info("$from : stopping HTTP server");

        try {
            challenge_http_server.close(force:true);
        }
        catch (e) {};

        try {
            await super.cleanup(from);
        }
        catch (e) {};

        try
        {
            challenge_websocket[prover["publicKey"]]?.close();
        }
        catch (e) {}

        cleanup_done            = true;
        client.in_a_challenge   = false;
    }
}

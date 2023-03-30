import "dart:io";
import "dart:math" as math;
import 'dart:async';
import "dart:convert";
import "dart:typed_data";

import "package:bit_array/bit_array.dart";

import "log.dart";
import "utils.dart";
import "constants.dart";
import "pob.dart" as pob;

final RNG = math.Random.secure();

class Client extends pob.Client
{
    bool init_done = false;

    Client (final Map args) : super ("prover", args)
    {
        // nothing
    }

    @override
    Future<bool> init () async
    {
        init_done   = await super.init();
        log         = LOG("Prover.Client", set_pob_client : this);

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

        assert(m["message_type"]                     == "challenge_for_prover");

        assert(ci["challengers"]                     is List);
        assert(ci["max_packets_per_challenger"]      is int);

        log.info("Number of challengers : ${ci['challengers'].length}");

        final challenge_start_time      = DateTime
                                            .parse(ci["challenge_start_time"])
                                            .toUtc()
                                            .millisecondsSinceEpoch;

        final now                       = DateTime
                                            .now()
                                            .toUtc()
                                            .millisecondsSinceEpoch;

        if (challenge_start_time > now)
        {
            final int diff          = challenge_start_time - now;
            final int wait_time     = (diff / 1000).ceil();

            final wait = Duration (seconds : wait_time - 10);

            if (wait.inSeconds > 0)
            {
                log.info("Waiting for ${wait_time-10} seconds");
                sleep (wait);
                log.success("Ready for challenge");
            }
        }

        challenge_handler = ChallengeHandler (ci, crypto, this);

        final challenge_timeout = DateTime
                                        .parse(ci["challenge_timeout"])
                                        .toUtc()
                                        .millisecondsSinceEpoch;

        final current_time      = DateTime
                                        .now()
                                        .toUtc()
                                        .millisecondsSinceEpoch;

        final timeout_in_milliseconds = challenge_timeout - current_time;

        log.important('Timeout : $timeout_in_milliseconds ms');

        Future.delayed(Duration(milliseconds : timeout_in_milliseconds), () async {
            await challenge_handler?.cleanup("Timeout");
        });

        await challenge_handler?.init();
        await challenge_handler?.run();

        return challenge_handler?.challenge_result ?? {};
    }
}

class ChallengeHandler extends pob.ChallengeHandler
{
    final Map <String,BitArray>   packet_bitmap     = {};
    final Map <String,int>        challenger_hash   = {};

    int hash_of_hashes  = 0;
    int uplink_rate     = 0; // Uplink backhaul of prover

    late List               challengers;
    final Map <String,bool> got_udp_pong = {};

    bool init_done  = false;

    late LOG log;

    ChallengeHandler
    (
        final Map           _challenge_info,
        final pob.Crypto    _crypto,
        final Client        _pob_client,
        {
            InternetAddress?    setSourceAddress4   = null,
            InternetAddress?    setSourceAddress6   = null,
            int                 setSourcePort       = 0,
        }
    ) : super
    (
            "prover",
            _challenge_info,
            _crypto,
            setSourceAddress4   : setSourceAddress4,
            setSourceAddress6   : setSourceAddress6,
            setSourcePort       : setSourcePort,
    )
    {
        pob_client  = _pob_client;
        log         = LOG("Prover.ChallengeHandler");
        challengers = challenge_info["challengers"];

        for (int i = 0; i < challengers.length; ++i)
        {
            final cpk           = challengers[i]["publicKey"];
            got_udp_pong [cpk]  = false;

            final IPv6          = challengers[i]["IPv6"];

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
        source_port = 1025 + RNG.nextInt(50000);
        init_done   = await super.init();

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
                log.success("1/7 DONE  send_udp_ping");
                log.important("2/7 START recv_udp_pong");

                if (await receive_udp_pong())
                {
                    log.success("2/7 DONE  recv_udp_pong");
                    log.important("3/7 START send_challenge_initiate_message");

                    if (await send_challenge_initiate_message())
                    {
                        log.success("3/7 DONE  send_challenge_initiate_message");
                        log.important("4/7 START received_enough_packets_for_challenge");

                        String result = await received_enough_packets_for_challenge();

                        log.success("4/7 DONE  $result : received_enough_packets_for_challenge");

                        if (result == "OK")
                        {
                            log.important("5/7 START send_hash_AND_hash_of_hashes");

                            if (await send_hash_AND_hash_of_hashes())
                            {
                                log.success("5/7 DONE  send_hash_AND_hash_of_hashes");
                                log.important("6/7 START send_all_hashes_AND_packet_bitmap");

                                if (await send_all_hashes_AND_packet_bitmap())
                                {
                                    log.success("6/7 DONE  send_all_hashes_AND_packet_bitmap");
                                    log.important("7/7 START send_end_challenge");

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

        socket4.close();
        socket6.close();

        return;
    }

    bool sent_all_packets_for_challenge_uplink() {
        int pktTxTime                   = (((UDP_CHUNK_SIZE + UDP_HEADER_SIZE) * 8) / uplink_rate).round() *
                                            challengers.length;
        int curTime                     = new DateTime.now().toUtc().microsecondsSinceEpoch;
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
            curTime = new DateTime
                            .now()
                            .toUtc()
                            .microsecondsSinceEpoch;
            while (curTime < nextTime) {
                curTime = new DateTime
                                .now()
                                .toUtc()
                                .microsecondsSinceEpoch;
            }
        }

        return true;
    }

    Future<String> received_enough_packets_for_challenge() async
    {
        final int?              max_packets_per_challenger      = challenge_info["max_packets_per_challenger"];
        final int?              total_num_packets_for_challenge = challenge_info["total_num_packets_for_challenge"];
        final String?           current_challenge_id            = challenge_info["challenge_id"];
        final String?           challenge_timeout               = challenge_info["challenge_timeout"];

        if (max_packets_per_challenger == null)
            return "max_packets_per_challenger is null";

        if (total_num_packets_for_challenge == null)
            return "total_num_packets_for_challenge is null";

        if (current_challenge_id == null)
            return "current_challenge_id is null";

        if (challenge_timeout == null)
            return "challenge_timeout is null";

        int num_packets_received = 0;

        while (num_packets_received < total_num_packets_for_challenge)
        {
            final Map signed_message = await get_UDP_message (
                        ["challenge_packet"],
                        verifySignature         : false,
                        processMessageFunction  : process_challenge_packet,
                        only_IPv6               : is_IPv6_challenge
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
        final udp_ping = jsonEncode ({
            "type" : "udp_ping",
            "data" : {
                "challenge_id"      : challenge_info ["challenge_id"],
                "timestamp"         : DateTime.now().toString(),
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
            await send_UDP_message (c, "udp_ping", signed_udp_ping);
        }

        return true;
    }

    Future<bool> receive_udp_pong() async
    {
        int num_udp_pongs_received = 0;

        final timeout = DateTime.now().add (
                Duration (milliseconds : 10000) // 10 seconds
        ).millisecondsSinceEpoch;

        while (num_udp_pongs_received < challengers.length)
        {
            final Map udp_pong  = await get_UDP_message (
                                ["udp_pong"],
                                timeout_in_milliseconds : 1000,
                                only_IPv6               : is_IPv6_challenge
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

            final now = DateTime.now().millisecondsSinceEpoch;

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
                "timestamp"         : DateTime.now().toString()
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
                    "timestamp"         : DateTime.now().toString(),
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
                "timestamp"     : DateTime.now().toString(),
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
                    "timestamp"     : DateTime.now().toString(),
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
                    "timestamp"     : DateTime.now().toString()
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

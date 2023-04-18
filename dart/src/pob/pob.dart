import "dart:io";
import "dart:core";
import "dart:convert";

import "package:ntp/ntp.dart"                                   as ntp;
import "package:http/http.dart"                                 as http;

import "../common/log.dart";
import "../common/utils.dart";
import "../common/crypto-factory.dart"                          as cryptoFactory;
import "../common/abc.dart"                                     as abc;

import "constants.dart";

class Client extends abc.Client
{
    Map args = {};

    Client (final String _role, final Map _args) : super (_role, _args)
    {
        args = _args;

        if (is_double(args,"bandwidth_claimed"))
                claims["bandwidth"] = args["bandwidth_claimed"];

        init_done = false;
    }

    Future<bool> init () async
    {
        if (init_done)
            return true;

        init_done = await super.init();

        log = LOG("pob.Client", set_client : this);

        if (! init_done)
            throw Exception("Could not initialize pob.Client");

        log.info("Version            : $POB_RELEASE_VERSION");

        if (ENV["NO_POB_UPDATES"] == null)
            log.success("Updates are turned : ON");
        else
            log.warning("Updates are turned : OFF");

        if (is_double(config,"bandwidth_claimed"))
            claims["bandwidth"] = args["bandwidth_claimed"];

        try
        {
            claims["bandwidth"] = double.parse (ENV["BANDWIDTH_CLAIMED"] ?? claims["bandwidth"].toString());
        }
        catch (e)
        {
            log.error("`BANDWIDTH_CLAIMED` environment variable is invalid");
        }

        if (claims["bandwidth"] == null || claims["bandwidth"] < 0.001)
            throw Exception("Invalid 'bandwidth' claimed");

        return (init_done = true);
    }

    Future<void> set_has_public_ip () async
    {
        if (run_set_has_public_ip == true)
            return;

        run_set_has_public_ip = true;

        Map j;  // json
        Map r;  // result

        // Try IPv6 first and then IPv4

        try
        {
            j       = await do_post (IP_INFO_URL_IPv6,{});
            r       = j["result"];

            IPv6    = r["IPv6"] ?? "INVALID";

            final clean_ip = process_ip(IPv6);

            if (clean_ip != IPv6)
            {
                IPv6 = "INVALID";
                IPv4 = clean_ip;
            }
        }
        catch (e) {}

        try
        {
            j       = await do_post (IP_INFO_URL_IPv4,{});
            r       = j["result"];

            IPv4    = r["IPv4"] ?? "INVALID";
        }
        catch (e) {}

        if (IPv4 == "INVALID" && IPv6 == "INVALID")
        {
                log.error("Your IP is : PRIVATE");
                return;
        }

        has_IPv6 = (IPv6 == "INVALID") ? false : true;

        final String secret_request = base64.encode (
            List<int>.generate(32, (i) => RNG.nextInt(256))
        );

        final String secret_response = base64.encode (
            List<int>.generate(32, (i) => RNG.nextInt(256))
        );

        if (IPv4 != "INVALID")
        {
            log.info("IPv4 is : $IPv4");

            HttpServer
                .bind(InternetAddress.anyIPv4, HTTP_IPv4_PORT)
                .then(
            (final server)
            {
                http_server4 = server;

                server.listen((final HttpRequest req)
                {
                    if (req.uri.path == "/" + secret_request)
                    {
                        req.response.write (secret_response);
                        req.response.close();
                    }
                    else
                    {
                        req.response.write("INVALID");
                        req.response.close();
                    }
                });
            });
        }

        if (IPv6 != "INVALID")
        {
            log.info("IPv6 is : $IPv6");

            HttpServer
                .bind(InternetAddress.anyIPv6, HTTP_IPv6_PORT)
                .then(
            (final server)
            {
                http_server6 = server;

                server.listen((final HttpRequest req)
                {
                    if (req.uri.path == "/" + secret_request)
                    {
                        req.response.write (secret_response);
                        req.response.close();
                    }
                    else
                    {
                        req.response.write("INVALID");
                        req.response.close();
                    }
                });
            });

            try
            {
                final open_bracket  = IPv6.contains(":") ? "[" : "";
                final close_bracket = IPv6.contains(":") ? "]" : "";

                final myself        = Uri.parse ("http://" + open_bracket + IPv6 + close_bracket + ":" + HTTP_IPv6_PORT.toString() + "/$secret_request");

                final response      = await http
                                        .get    (myself)
                                        .timeout (const Duration(seconds: 5),
                                            onTimeout: () {
                                                log.error("Self connect to IPv6 timedout");
                                                return http.Response('Error', 408);
                                            }
                                        );


                final got_text      = response
                                        .body
                                        .replaceAll("\r","")
                                        .replaceAll("\n","");

                if (got_text == secret_response)
                {
                    has_public_IPv6 = true;

                    log.success("Your IPv6 `$IPv6` is : PUBLIC");
                }
                else
                {
                    log.warning("Your IPv6 `$IPv6` is : PRIVATE");
                }
            }
            catch (e)
            {
                log.warning("Your IPv6 `$IPv6` is : PRIVATE");
            }
        }

        try
        {
            final myself        = Uri.parse ("http://" + IPv4 + ":" + HTTP_IPv4_PORT.toString()  + "/$secret_request");
            final response      = await http
                                        .get    (myself)
                                        .timeout (const Duration(seconds: 5),
                                            onTimeout: () {
                                                log.error("Self connect to IPv4 timedout");
                                                return http.Response('Error', 408);
                                            }
                                        );

            final got_text      = response
                                        .body
                                        .replaceAll("\r","")
                                        .replaceAll("\n","");

            if (got_text == secret_response)
            {
                has_public_IPv4 = true;

                log.success("Your IPv4 `$IPv4` is : PUBLIC");
            }
            else
            {
                log.warning("Your IPv4 `$IPv4` is : PRIVATE");
            }
        }
        catch (e)
        {
            log.warning("Your IPv4 `$IPv4` is : PRIVATE");
        }

        http_server4?.close(force:true);
        http_server6?.close(force:true);
    }

    void Log (final String icon, final String message)
    {
        final now   = Now(ntp_offset);
        final time  = now.month.toString() + "/" + now.day.toString() + " " + now.hour.toString() + ":" + now.minute.toString();
        final line  = "$icon $time $message";

        if (logs_length >= 40)
        {
                final split = logs.split("\n").sublist(0,38);
                logs = split.join("\n");
                logs_length = 39;
        }

        logs = line + "\n" + logs;

        ++logs_length;
    }

    Future<Map> do_post (final Uri uri, final Map body) async
    {
        String json_body        = jsonEncode(body);

        final headers           = {
                "Content-Type"  : "application/json",
                "Cookie"        : cookie
        };

        final response = await http.post (
                uri,
                body    : json_body,
                headers : headers
        );

        final c = response.headers["set-cookie"];

        if (c != null)
        {
                const cookie_name       = "__Secure-session=";
                const cookie_signature  = "__Secure-session.sig=";

                cookie = "";

                cookie += cookie_name;
                cookie += c.split(cookie_name)[1].split(";")[0];

                cookie += "; ";

                cookie += cookie_signature;
                cookie += c.split(cookie_signature)[1].split(";")[0];
        }

        Map j = {};

        if (response.headers["content-type"] == "application/json")
        {
                try
                {
                        j = jsonDecode(response.body);

                        if (response.statusCode != 200)
                                log.error("${uri.path}: " + j["error"]["message"]);

                        if (response.statusCode == 402)
                        {
                            do_run                      = false;
                            payment_or_staking_required = true;
                        }
                }
                catch (e)
                {
                        print("Exception $e");
                }
        }
        else
        {
                log.error("Server did not return 'application/json'");
        }

        return j;
    }
}

class ChallengeHandler extends abc.ChallengeHandler
{
    InternetAddress             source_address4  = InternetAddress.anyIPv4;
    InternetAddress             source_address6  = InternetAddress.anyIPv6;

    late int                    source_port;
    late int                    destination_port;

    late RawDatagramSocket      socket4;
    late RawDatagramSocket      socket6;

    late abc.Crypto             crypto;

    List whitelist              = [];

    final Map challenge_result  = {};

    int startTime               = -1;
    int endTime                 = -1;

    late LOG log;
    late LOG ws_log;

    bool challenge_succeeded    = false;
    bool is_IPv6_challenge      = false;

    late DateTime last_message_received_time;

    late String challenge_id;
    late List<int> challenge_id_in_ascii;

    late Duration ntp_offset;

    Map<String,WebSocket>   challenge_websocket = {};
    late HttpServer         challenge_http_server;

    ChallengeHandler
    (
        final String    _role,
        final Map       _challenge_info,
        this.crypto,
        {
            InternetAddress?    setSourceAddress4   = null,
            InternetAddress?    setSourceAddress6   = null,
            int                 setSourcePort       = 0
        }
    ) : super (_role, _challenge_info)
    {
        int? mppc = challenge_info ["max_packets_per_challenger"];

        if (mppc == null)
            throw Exception("Did not get max_packets_per_challenger");

        source_port         = (role == "prover") ? PROVER_PORT      : CHALLENGER_PORT;
        destination_port    = (role == "prover") ? CHALLENGER_PORT  : PROVER_PORT;

        if (setSourceAddress4 != null)
            source_address4 = setSourceAddress4;

        if (setSourceAddress6 != null)
            source_address6 = setSourceAddress6;

        if (setSourcePort > 0)
            source_port = setSourcePort;

        challenge_id            = challenge_info["challenge_id"] ?? "INVALID";
        challenge_id_in_ascii   = ascii.encode(challenge_id);
    }

    @override
    Future<bool> init () async
    {
        await crypto.init();

        ntp_offset = Duration (milliseconds : await ntp.NTP.getNtpOffset());

        log     = LOG("ChallengeHandler", set_client : client);
        ws_log  = LOG("WebSocket.Message",set_client : client);

        try
        {
            socket4 = await RawDatagramSocket.bind (
                source_address4,
                source_port,
                reusePort : (role == "prover")
            );
        }
        catch (e) {print("Bind socket4 Exception $e");}

        try
        {
            socket6 = await RawDatagramSocket.bind (
                source_address6,
                source_port,
                reusePort : (role == "prover")
            );
        }
        catch (e) {print("Bind socket6 Exception $e");}

        return true;
    }

    Future<bool> send_message (final Map to, final String message_type, final Map message) async
    {
        switch (message_type)
        {
            case "udp_ping"                 :
            case "udp_pong"                 :
            case "challenge_packet"         :
            case "hash_AND_hash_of_hashes"  :
                return send_UDP_message (to,message_type,message);

            default:
                return send_websocket_message (to,message_type,message);
        }
    }

    Future<bool> send_websocket_message (final Map to, final String message_type, final Map message) async
    {
        final publicKey = to["publicKey"];
        final ws        = challenge_websocket[publicKey];

        if (publicKey == null || ws == null)
        {
            log.error("No websocket found to send ${message_type} to $publicKey");

            return false;
        }
        else
        {
            ws.add(jsonEncode(message));
            log.important("Sending ${message_type} to $publicKey");

            return true;
        }
    }

    bool send_UDP_message (final Map to, final String message_type, final Map message_map)
    {
        final   message     = jsonEncode(message_map).codeUnits;

        final   destination = to["ip"];
        final   dport       = to["udp_port"] ?? destination_port;
        final   socket      = (destination.type == InternetAddressType.IPv6) ? socket6 : socket4;

        for (int i = 1; i <= 10; ++i)
        {
            final sent = socket.send (
                message,
                destination,
                dport
            );

            if (sent == message.length)
            {
                log.success("Sent : $message_type");
                return true;
            }
        }

        return false;
    }

    bool send_UDP_message_bytes (final Map to, final String message_type, final List<int> message)
    {
        final   destination = to["ip"];
        final   dport       = to["udp_port"] ?? destination_port;
        final   socket      = (destination.type == InternetAddressType.IPv6) ? socket6 : socket4;

        for (int i = 1; i <= 10; ++i)
        {
            final sent = socket.send (
                message,
                destination,
                dport
            );

            if (sent == message.length)
            {
                return true;
            }
        }
        log.error("could not send $message_type to $to");
        return false;
    }

    Future<Map> get_UDP_message
    (
        final List<String> expected_message_types,
        {
            final   bool    verifySignature         = true,
            final   dynamic processMessageFunction  = null,
            final   int     timeout_in_milliseconds = 0,
            final   bool    only_IPv6               = false
        }
    ) async
    {
        final timeout = (timeout_in_milliseconds == 0)  ?
                                            0           :
                                            Now (ntp_offset)
                                            .add (
                                                Duration (
                                                    milliseconds : timeout_in_milliseconds
                                                )
                                            ).millisecondsSinceEpoch;

        while (true)
        {
            Datagram? datagram  = null;
            String ip_version   = "";

            if (only_IPv6)
            {
                datagram        = socket6.receive();
                ip_version      = "IPv6";
            }
            else
            {
                datagram        = socket4.receive();
                ip_version      = "IPv4";
            }

            if (datagram == null || datagram.data.length == 0 || datagram.data.length > UDP_CHUNK_SIZE)
            {
                if (timeout > 0)
                {
                    final now = Now(ntp_offset).millisecondsSinceEpoch;

                    if (now > timeout)
                    {
                        log.error("timeout happened for $expected_message_types");
                        return {};
                    }
                }

                continue;
            }

            last_message_received_time = Now(ntp_offset);

            final sender_address    = datagram.address.address;
            final clean_address     = process_ip (sender_address);

            if (ip_version == "IPv6" && sender_address != clean_address)
            {
                ip_version = "IPv4";
            }

            final sender_ip         = (ip_version == "IPv6") ?
                                                    Uri.parseIPv6Address(clean_address):
                                                    Uri.parseIPv4Address(clean_address);

            // if the user has specified a custom processMessageFunction, then process accordingly

            if (processMessageFunction != null)
                return await processMessageFunction(datagram.data);

            // else process the message as a JSON

            try
            {
                final String string_signed_message = String.fromCharCodes(datagram.data);

                final Map signed_message = await process_message_as_json (
                    string_signed_message,
                    sender_ip,
                    ip_version,
                    datagram.port,
                    verifySignature : verifySignature
                );

                final Map message         = jsonDecode(signed_message["message"]);
                final String message_type = message["type"];

                if (expected_message_types.contains(message_type))
                    return signed_message;
                else
                {
                    // XXX store `m` in a queue ?
                    return {};
                }
            }
            catch (e)
            {
                print("GOT exception $e");
                continue;
            }
        }
    }

    Future<Map> process_message_as_json
    (
        final String    string_signed_message,
        final List<int> sender_ip,
        final String    ip_version,
        final int       port,
        {
            final bool  verifySignature = true
        }
    ) async
    {
        Map signed_message = {};

        try
        {
            signed_message = jsonDecode (string_signed_message);
        }
        catch (e)
        {
            log.error("$string_signed_message is not a valid JSON");
            return {};
        }

        final String string_message = signed_message["message"];

        Map message = {};

        try
        {
            message = jsonDecode (string_message);
        }
        catch(e)
        {
            log.error("Could not convert string_message to Json : $e");
            return {};
        }

        // the data in the message
        final Map data = message["data"];

        // reject invalid challenge id
        if (data["challenge_id"] != challenge_id)
            return {};

        final sender = {
            ip_version  : sender_ip,
            "keyType"   : signed_message["keyType"],
            "publicKey" : signed_message["publicKey"],
        };

        bool allowed = false;

        if (whitelist.length > 0)
        {
            for (final w in whitelist)
            {
                final whitelist_address = w[ip_version]; // address

                if (whitelist_address == null)
                    continue;

                // ip in list format

                final whitelist_ip  = (ip_version == "IPv6") ?
                                            Uri.parseIPv6Address(whitelist_address):
                                            Uri.parseIPv4Address(whitelist_address);

                if (
                    sender["keyType"]   == w["keyType"]     &&
                    sender["publicKey"] == w["publicKey"]   &&
                    (
                        is_list_equals (sender_ip, whitelist_ip)
                    )
                )
                {
                    allowed = true;
                    break;
                }
             }

             if (! allowed)
                return {};
        }

        if (verifySignature)
        {
            if (! await cryptoFactory.verify (signed_message))
                return {};
        }

        signed_message["DATA"] = data;

        if (port > 0)
        {
            signed_message["SOURCE_PORT"]  = port;
        }

        final message_type = message["type"];

        if (message_type == null)
        {
            log.error("message type is empty");
            return {};
        }

        return signed_message;
    }

    Future<void> start_websocket_server () async
    {
        final port              = (role == "prover") ? PROVER_PORT : CHALLENGER_PORT;
        challenge_http_server   = await HttpServer.bind(InternetAddress.anyIPv6, port);

        challenge_http_server.forEach
        (
            (final HttpRequest request) async
            {
                switch (request.uri.path)
                {
                    case "/":
                    {
                        request.response.statusCode = HttpStatus.ok;
                        request.response.close();

                        return;
                    }

                    case "/ws":
                    {
                        if (challenge_info["challenge_id"] != request.uri.queryParameters["challenge_id"])
                        {
                            request.response.statusCode = HttpStatus.forbidden;
                            request.response.close();

                            return;
                        }

                        final socket    = await WebSocketTransformer.upgrade(request);
                        final ip        = request.connectionInfo?.remoteAddress ?? InternetAddress("");

                        await socket.listen((message) async
                        {
                            await handle_challenge_message (message,ip,socket);
                        });

                        return;
                    }

                    default:
                    {
                        request.response.statusCode = HttpStatus.forbidden;
                        request.response.close();

                        return;
                    }
                }
            }
        );

        await connect_to_self(port);
    }

    Future<void> connect_to_self (int port) async
    {
        while (true)
        {
            try
            {
                final response = await http.get(Uri.parse("http://127.0.0.1:" + port.toString()));

                if (response.statusCode == HttpStatus.ok)
                {
                    log.success("WebSocket server started");
                    return;
                }
            }
            catch (e)
            {
                log.error("Exception $e");
                sleep (FOR_2_SECONDS);
            }
        }
    }

    Future<void> start_websocket_client (String host, String publicKey) async
    {
        if (host.contains(":"))
            host = "[" + host + "]";

        final port          = role == "prover" ? CHALLENGER_PORT : PROVER_PORT;
        final challenge_id  = challenge_info["challenge_id"];

        for (int i = 1; i <= 10; ++i)
        {
            try
            {
                ws_log.important("Connecting to WebSocket of : $host ...");

                challenge_websocket[publicKey] = await WebSocket.connect("ws://" + host + ":" + port.toString()  + "/ws?challenge_id=$challenge_id");

                ws_log.success("Connected to WebSocket of : $host");

                final websocket_connect = jsonEncode ({
                    "type" : "websocket_connect",
                    "data" : {
                        "challenge_id"      : challenge_id,
                        "timestamp"         : Now(ntp_offset).toString(),
                    }
                });

                final signed_websocket_connect = jsonEncode ({
                    "message"     : websocket_connect,
                    "keyType"     : crypto.keyType,
                    "publicKey"   : crypto.publicKey,
                    "signature"   : await crypto.sign(websocket_connect),
                });

                final ws = challenge_websocket[publicKey];

                if (ws == null)
                    return;

                ws.add(signed_websocket_connect);

                await ws.listen((message) async
                {
                        await handle_challenge_message (message, InternetAddress(host), ws);
                });

                return;
            }
            catch(e)
            {
                ws_log.warning("Failed to connect $i times");
                sleep (FOR_2_SECONDS);
            }
        }

        ws_log.error("Cannot connect host : $host");
    }

    Future<void> handle_challenge_message (final String message, final InternetAddress sender, final WebSocket ws)
    {
        throw Exception("This is an abstract method!");
    }

    Future<void> cleanup (final String from) async
    {
        log.info("$from : sockets.close");

        try
        {
            socket4.close();
        }
        catch (e) {}

        try
        {
            socket6.close();
        }
        catch (e) {}

        try
        {
            challenge_http_server.close(force: true);
        }
        catch (e) {}

        client.in_a_challenge = false;
    }
}

import "dart:io";
import "dart:core";
import "dart:convert";

import "package:http/http.dart"                                 as http;
import "package:web_socket_channel/status.dart"                 as status;

import "package:stream_channel/stream_channel.dart";
import "package:web_socket_channel/web_socket_channel.dart";

import "log.dart";
import "utils.dart";
import "constants.dart";
import "crypto_factory.dart"                                    as cryptoFactory;

class Crypto
{
    String          keyType                 = "INVALID";
    String          publicKey               = "INVALID";
    String          walletPublicKey         = "INVALID";
    String          id_file                 = "INVALID";

    /// We don't know the type of keyPair yet
    var             keyPair                 = null;

    Crypto (final String _keyType, final Map args)
    {
        keyType = _keyType;

        if (is_string(args, "publicKey"))
            publicKey = args["publicKey"];

        if (is_string(args, "id_file"))
            id_file = args["id_file"];

        if (args.containsKey("keyPair"))
            keyPair = args["keyPair"];

        if (args.containsKey("keyType"))
            keyType = args["keyType"];

        if (is_string(args, "walletPublicKey"))
            walletPublicKey = args["walletPublicKey"];
    }

    Future<bool> init() async
    {
       return true;
    }

    Future<String> sign (final String message) async
    {
        return "INVALID";
    }

    static Future<bool> verify (final String message, final String signature, final String public_key) async
    {
        return false;
    }

    Future<bool> save_keyPair () async
    {
       return false;
    }

    static int signature_length_in_bytes ()
    {
        return 0;
    }
}

class Client
{
    String          role                    = "INVALID";
    late Crypto     crypto;

    String?         projectName;
    String?         projectPublicKey;

    String          cookie                  = "";

    bool            do_run                  = false;

    late String                             configFile;

    String          logs                    = "";
    int             logs_length             = 0;
    bool            logs_on_terminal        = true;

    bool            has_public_ip           = false;
    bool            has_IPv6                = false;

    bool            websocket_IPv4_running  = false;
    bool            websocket_IPv6_running  = false;

    bool            in_a_challenge          = false;

    ChallengeHandler?   challenge_handler   = null;

    bool            init_done               = false;

    late LOG log;

    final Map connected_websockets          = {};

    HttpServer? http_server                 = null;

    bool    payment_or_staking_required     = false; // server expects some payment/staking

    bool logged_in                          = false;


    // all variables claimed by the client

    double          bandwidth_claimed       = 0.0;

    Client (final String _role, final Map args)
    {
        role = _role.toLowerCase();

        if (args.containsKey("crypto"))
                crypto = args["crypto"];
        else
                crypto = cryptoFactory.create(args);

        if (is_string(args,"projectName"))
                projectName = args["projectName"];

        if (is_string(args,"projectPublicKey"))
                projectPublicKey = args["projectPublicKey"];

        if (is_double(args,"bandwidth_claimed"))
                bandwidth_claimed = args["bandwidth_claimed"];

        if (is_bool(args,"logs_on_terminal"))
                logs_on_terminal = args["logs_on_terminal"];

        if (is_string(args,"configFile"))
                configFile = args["configFile"];
        else
                configFile = role + ".json";
    }

    Future<bool> init () async // common init for all kinds of login
    {
        if (init_done)
            return true;

        log = LOG("Client", set_pob_client : this);

        final List CONFIG_FILES = [
            "../config/" + configFile,
            "./config/"  + configFile,
            "./"         + configFile
        ];

        log.info("Version   : $POB_RELEASE_VERSION");

        for (final cf in CONFIG_FILES)
        {
            try
            {
                final Map config = jsonDecode (
                    File(cf).readAsStringSync()
                );

                log.success("Read : $cf");

                if (is_string(config,"walletPublicKey"))
                {
                    crypto.walletPublicKey = config["walletPublicKey"];
                    log.important("SET : 'walletPublicKey'   = ${crypto.walletPublicKey.substring(0,7)}...");
                }

                if (is_double(config,"bandwidth_claimed"))
                {
                    bandwidth_claimed = config["bandwidth_claimed"];
                    log.important("SET : 'bandwidth_claimed' = $bandwidth_claimed");
                }
            }
            catch (e) {}
        }

        crypto.walletPublicKey = ENV["WALLET_PUBLIC_KEY"] ?? crypto.walletPublicKey;

        try
        {
            bandwidth_claimed = double.parse (ENV["BANDWIDTH_CLAIMED"] ?? bandwidth_claimed.toString());
        }
        catch (e)
        {
            log.error("`BANDWIDTH_CLAIMED` environment variable is invalid");
        }

        if (bandwidth_claimed < 0.001)
            throw Exception("Invalid bandwidth_claimed");

        bool found_invalid_walletPublicKey = false;

        if (crypto.walletPublicKey == "INVALID")
        {
            found_invalid_walletPublicKey = true;

            stdout.write("Could not find 'walletPublicKey' in '$role.json'; please enter it : ");
            crypto.walletPublicKey = stdin.readLineSync() ?? "INVALID";
        }

        // walletPublicKey was found invalid -BUT- now looks like is valid

        if (found_invalid_walletPublicKey == true && crypto.walletPublicKey != "INVALID")
        {
            try
            {
                log.info("Saving 'walletPublicKey' and 'bandwidth_claimed' in '$role.json' ...");

                final f = await File(role + ".json").create();
                f.writeAsStringSync('{"walletPublicKey" : "${crypto.walletPublicKey}", "bandwidth_claimed" : $bandwidth_claimed}');

                log.success("Saved  'walletPublicKey' and 'bandwidth_claimed' in '$role.json'");
            }
            catch (e) {}
        }

        return (init_done = true);
    }

    Future<void> set_has_public_ip () async
    {
        if (! logged_in)
            return;

        Map j;  // json
        Map r;  // result

        String IPv4 = "INVALID";
        String IPv6 = "INVALID";

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
                has_public_ip = false;

                log.error("Your IP is : PRIVATE");

                return;
        }

        has_IPv6 = (IPv6 == "INVALID") ? false : true;

        if (has_IPv6)
            await run_websocket_IPv6();

        if (IPv4 != "INVALID")
            log.info("IPv4 is : $IPv4");

        if (IPv6 != "INVALID")
            log.info("IPv6 is : $IPv6");

        final String secret_request = base64.encode (
                List<int>.generate(32, (i) => RNG.nextInt(256))
        );

        final String secret_response = base64.encode (
                List<int>.generate(32, (i) => RNG.nextInt(256))
        );

        final MyIP = process_ip (IPv6 == "INVALID" ? IPv4 : IPv6);

        HttpServer
                .bind(InternetAddress.anyIPv6, 8888)
                .then(
        (final server)
        {
            http_server = server;

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
            final open_bracket  = MyIP.contains(":") ? "[" : "";
            final close_bracket = MyIP.contains(":") ? "]" : "";

            final myself        = Uri.parse ("http://" + open_bracket + MyIP + close_bracket + ":8888/$secret_request");
            final response      = await http.get(myself);

            final got_text      = response
                                        .body
                                        .replaceAll("\r","")
                                        .replaceAll("\n","");

            if (got_text == secret_response)
            {
                has_public_ip = true;

                log.success("Your IP is : PUBLIC");

                return;
            }
        }
        catch (e) {}

        http_server?.close(force:true);
        has_public_ip = false;

        log.error("Your IP is : PRIVATE");
    }

    void Log (final String icon, final String message)
    {
        final now   = DateTime.now().toUtc();
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

    Future<bool> login () async
    {
        await init();
        await crypto.init();

        final p = "PublicKey : ${crypto.publicKey}".substring(0,20) + "...";

        log.info("Role      : $role");
        log.info(p);
        log.info("Bandwidth : $bandwidth_claimed Mbps");

        final Map pre_login_body = {
                "role"                  : role,
                "bandwidth_claimed"     : bandwidth_claimed,
                "projectName"           : projectName,
                "projectPublicKey"      : projectPublicKey,

                "keyType"               : crypto.keyType,
                "publicKey"             : crypto.publicKey,
                "walletPublicKey"       : crypto.walletPublicKey,

                "clientVersion"         : POB_RELEASE_VERSION,
        };

        final Map j = await do_post (PRE_LOGIN_URL, pre_login_body);

        ///////////////////////////////////////////////////////////

        if (j["result"] == null)
            return (logged_in = false);

        final String message    = j["result"]["message"];

        final String signature  = await crypto.sign(message);

        final Map login_body = {
                "message"       : message,
                "signature"     : signature
        };

        await do_post (LOGIN_URL,login_body);

        set_has_public_ip();

        return (logged_in = true);
    }

    Future<bool> logout () async
    {
        final Map body = {};

        await do_post (LOGOUT_URL,body);

        return true;
    }

    Future<void> run () async
    {
        if (cookie == "" || logged_in == false)
            throw Exception("Login did not succeed");

        do_run = true;

        while (do_run && payment_or_staking_required == false) // until user stops -OR- some exception occurs
        {
            final ws6 = run_websocket_IPv6();
            final ws4 = run_websocket_IPv4();

            await ws6;
            websocket_IPv6_running = false;

            await ws4;
            websocket_IPv4_running = false;

            sleep (FOR_2_SECONDS);
        }
    }

    Future<Map> handle_websocket (final Map m) async
    {
        throw Exception("Use Prover/Challenger class instead");
    }

    Future<void> cleanup (final String from) async
    {
        do_run = false;

        log.info("$from : cleanup PoB");

        http_server?.close          (force:true);
        challenge_handler?.cleanup  ("PoB.Client");

        try
        {
            connected_websockets["IPv4"]?.sink.close(status.goingAway);
        }
        catch (e) {}

        try
        {
            connected_websockets["IPv6"]?.sink.close(status.goingAway);
        }
        catch (e) {}

        log.important("Done Running");
    }

    Future<void> run_websocket_IPv4 () async
    {
        if (! logged_in || websocket_IPv4_running)
            return;

        while (do_run) // until user stops -OR- some exception occurs
        {
            websocket_IPv4_running = true;
                await run_websocket (WEBSOCKET_GET_URL_IPv4,"IPv4");
            websocket_IPv4_running = false;

            sleep (FOR_2_SECONDS);
        }

        websocket_IPv4_running = false;
    }

    Future<void> run_websocket_IPv6 () async
    {
        if (! logged_in || ! has_IPv6)
            return;

        if (websocket_IPv6_running)
            return;

        while (do_run && payment_or_staking_required == false) // until user stops -OR- some exception occurs
        {
            websocket_IPv6_running = true;
                await run_websocket (WEBSOCKET_GET_URL_IPv6,"IPv6");
            websocket_IPv6_running = false;

            sleep (FOR_2_SECONDS);
        }

        websocket_IPv6_running = false;
    }

    Future<bool> run_websocket (final Uri url, final String ip_version) async
    {
        if (payment_or_staking_required)
            return false;

        final HttpClient client = HttpClient();
        final request           = await client.openUrl ("GET",url);

        final String sec_websocket_key = base64.encode (
                List<int>.generate(16, (i) => RNG.nextInt(256))
        );

        request.headers
                ..set("Upgrade",                "websocket")
                ..set("Connection",             "Upgrade")
                ..set("Cookie",                 cookie)
                ..set("Sec-WebSocket-Key",      sec_websocket_key)
                ..set("Sec-WebSocket-Version",  "13");

        final response          = await request.close();
        final socket            = await response.detachSocket();

        final innerChannel      = StreamChannel<List<int>> (
                                        socket,
                                        socket
                                );

        final every_30_seconds  = Duration (seconds : 30);

        final ws                = WebSocketChannel (
                                        innerChannel,
                                        pingInterval    : every_30_seconds,
                                        serverSide      : false
                                );

        connected_websockets [ip_version] = ws;

        log.success("Connected to WS : $ip_version");

        ws.stream.listen (
                (final msg) async
                {
                        Map json_msg = {};

                        try
                        {
                                json_msg = jsonDecode(msg);
                        }
                        catch (e)
                        {
                                log.error("Invalid message from server ($ip_version)");
                                return;
                        }

                        log.important("Got a challenge : $ip_version");

                        handle_websocket(json_msg);
                },
                onDone  : () async
                {
                        try {
                                ws.sink.close(status.goingAway);
                        } catch (e) {}
                },
                onError: (Object error, StackTrace stackTrace) async
                {
                        try {
                                ws.sink.close(status.goingAway);
                        } catch (e) {}

                        log.error("$ip_version : $error");
                },
        );

        await ws.sink.done.then((x)
        {
                log.error("WS closed : $ip_version");
        });

        return true;
    }

    Future<void> report_challenge_results (final ChallengeHandler ch) async
    {
        throw Exception("This is an abstract method");
    }
}

class ChallengeHandler
{
    late Client                 pob_client;

    Map                         challenge_info  = {};

    late String                 role;

    InternetAddress             source_address4  = InternetAddress.anyIPv4;
    InternetAddress             source_address6  = InternetAddress.anyIPv6;

    late int                    source_port;
    late int                    destination_port;

    late RawDatagramSocket      socket4;
    late RawDatagramSocket      socket6;

    late Crypto                 crypto;

    List whitelist              = [];

    final Map challenge_result  = {};

    int startTime               = -1;
    int endTime                 = -1;

    late LOG log;

    bool challenge_succeeded    = false;
    bool is_IPv6_challenge      = false;

    late DateTime last_message_received_time;

    late String challenge_id;
    late List<int> challenge_id_in_ascii;

    ChallengeHandler
    (
        this.role,
        this.challenge_info,
        this.crypto,
        {
            InternetAddress?    setSourceAddress4   = null,
            InternetAddress?    setSourceAddress6   = null,
            int                 setSourcePort       = 0
        }
    )
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

    Future<bool> init () async
    {
        await crypto.init();

        log = LOG("ChallengeHandler", set_pob_client : pob_client);

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

    Future<bool> run () async
    {
        throw Exception("Is an abstract method!");
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
                return send_TCP_message (to,message_type,message);
        }
    }

    Future<bool> send_TCP_message (final Map to, final String message_type, final Map message) async
    {
        final http_port = ":8080"; //destination_port.toString();

        const post_path = {
            "start_challenge"           : "/start-challenge",
            "all_hashes"                : "/send-results",
            "packet_bitmap"             : "/send-results",
            "end_challenge"             : "/end-challenge",
        };

        final String? path = post_path [message_type];

        if (path == null)
            return false;

        final destination = to["ip"];

        if (destination == null)
        {
            log.error("send_TCP_message : destination was null");
            return false;
        }

        String host = destination.address;

        if (host.contains(":"))
            host = "[" + host + "]";

        final uri = Uri.parse("http://" + host + http_port + path);

        log.important("${message_type} to $uri");

        final response = await http.post (
            uri,
            body    : jsonEncode (message),
            headers : CONTENT_TYPE_JSON
        );

        if (response.statusCode == 200)
            log.success ("$message_type : $uri ");
        else
            log.error   ("$message_type : $uri ");

        return (response.statusCode == HttpStatus.ok);
    }

    bool send_UDP_message (final Map to, final String message_type, final Map message_map)
    {
        final   message     = jsonEncode(message_map).codeUnits;

        final   destination = to["ip"];
        final   dport       = to["port"] ?? destination_port;
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
        final   dport       = to["port"] ?? destination_port;
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
                                            DateTime.now().add (
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
                    final now = DateTime.now().millisecondsSinceEpoch;

                    if (now > timeout)
                        return {};
                }

                continue;
            }

            last_message_received_time = DateTime.now();

            final sender_address    = datagram.address.address;
            final sender_ip         = (ip_version == "IPv6") ?
                                                    Uri.parseIPv6Address(sender_address):
                                                    Uri.parseIPv4Address(sender_address);

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
            log.error("string_signed_message is not a valid JSON");
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

        pob_client.in_a_challenge = false;
    }
}

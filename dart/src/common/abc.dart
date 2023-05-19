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
import "dart:core";
import "dart:convert";

import "package:ntp/ntp.dart"                                   as ntp;
import "package:http/http.dart"                                 as http;
import "package:web_socket_channel/status.dart"                 as status;

import "package:stream_channel/stream_channel.dart";
import "package:web_socket_channel/web_socket_channel.dart";

import "log.dart";
import "utils.dart";
import "constants.dart";
import "crypto-factory.dart"                                    as cryptoFactory;

class Crypto
{
    String          keyType                 = "INVALID";
    String          publicKey               = "INVALID";
    String          id_file                 = "INVALID";

    Map             walletPublicKey         = {};

    bool            init_done               = false;

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

        if (args["walletPublicKey"] is Map)
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
    String          proof_type              = "INVALID";
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

    String          IPv4                    = "INVALID";
    String          IPv6                    = "INVALID";

    bool            has_public_IPv4         = false;
    bool            has_public_IPv6         = false;

    bool            websocket_IPv4_running  = false;
    bool            websocket_IPv6_running  = false;

    bool            in_a_challenge          = false;

    bool            init_done               = false;

    late LOG        log;
    late LOG        ws_log;

    final Map       connected_websockets    = {};

    HttpServer?     http_server4            = null;
    HttpServer?     http_server6            = null;

    late Duration   ntp_offset;

    final Map       config                  = {};
    Map             claims                  = {};       // all things claimed by the client

    bool    payment_or_staking_required     = false;    // server expects some payment/staking
    bool    logged_in                       = false;
    bool    done_setting_public_ip          = false;

    Client (this.proof_type, this.role, final Map args)
    {
        if (args.containsKey("crypto"))
            crypto = args["crypto"];
        else
            crypto = cryptoFactory.create(args);

        if (is_string(args,"projectName"))
            projectName = args["projectName"];

        if (is_string(args,"projectPublicKey"))
            projectPublicKey = args["projectPublicKey"];

        if (is_bool(args,"logs_on_terminal"))
            logs_on_terminal = args["logs_on_terminal"];

        if (is_string(args,"configFile"))
            configFile = args["configFile"];
        else
            configFile = role + ".json";
    }

    Future<bool> init () async
    {
        if (init_done)
            return true;

        ntp_offset = Duration (milliseconds : await ntp.NTP.getNtpOffset());

        log = LOG("Client", set_client : this);

        final List CONFIG_FILES = [
            "../config/" + configFile,
            "./config/"  + configFile,
            "./"         + configFile
        ];

        for (final cf in CONFIG_FILES)
        {
            String json_string = "{}";

            try
            {
                json_string = File(cf).readAsStringSync();
            }
            catch (e)
            {
                continue;
            }

            try
            {
                final Map c = jsonDecode (json_string);

                log.success("Read : $cf");

                c.forEach
                (
                    (final k, final v)
                    {
                        if (! k.startsWith("//"))
                        {
                            config[k] = v;
                            log.important("Considering : '$k' = '$v'");
                        }
                    }
                );
            }
            catch (e)
            {
                log.success ("Found the file : `$cf`");
                log.error   ("However, it appears to contain invalid JSON : $e\n");
            }
        }

        claims                  = config["claims"]          ?? claims;
        crypto.walletPublicKey  = config["walletPublicKey"] ?? {};

        if (ENV["WALLET_PUBLIC_KEY"] != null)
        {
            crypto.walletPublicKey = {
                crypto.keyType : ENV["WALLET_PUBLIC_KEY"]
            };
        }

        if (crypto.walletPublicKey.length == 0)
        {
            log.error       ("Could NOT find 'walletPublicKey' in '$role.json';");
            log.important   (">>> Please enter it as keyType:walletPublicKey");
            log.warning     (">>> Example `solana:publicKey-of-Solana-Wallet`");

            final input = stdin.readLineSync() ?? ":";

            final split_semicolon = input.split(";");

            for (final wallet in split_semicolon)
            {
                final s = wallet.split(":");

                final k = s[0].trim();
                final v = s[1].trim();

                if (k == "" || v == "")
                    continue;

                crypto.walletPublicKey [k] = v;

                log.important ("Setting wallet : $k = $v");
            }

            if (crypto.walletPublicKey.length > 0)
            {
                try
                {
                    log.info("Saving 'walletPublicKey' and 'claims' in '$role.json' ...");

                    switch (proof_type)
                    {
                        case "pob":
                        {
                            if (claims["bandwidth"] == null)
                                claims["bandwidth"] = 10;

                            break;
                        }
                    }

                    final save_config = {
                        "claims"            : claims,
                        "walletPublicKey"   : crypto.walletPublicKey
                    };

                    final f = await File(role + ".json").create();
                    f.writeAsStringSync(jsonEncode(save_config));

                    log.success("Saved 'walletPublicKey' and 'claims' in '$role.json'");
                }
                catch (e) {}
            }
        }

        return (init_done = true);
    }

    Future<void> set_has_public_ip () async
    {
        if (done_setting_public_ip == true)
            return;

        done_setting_public_ip = true;

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

        final String secret_request = base64.encode (
            List<int>.generate(32, (i) => RNG.nextInt(256))
        );

        final String secret_response = base64.encode (
            List<int>.generate(32, (i) => RNG.nextInt(256))
        );

        if (IPv4 != "INVALID")
        {
            log.info("IPv4 is   : $IPv4");

            HttpServer
                .bind (InternetAddress.anyIPv4, HTTP_IPv4_PORT)
                .then
            (
                (final server)
                {
                    http_server4 = server;

                    server.listen
                    (
                        (final HttpRequest req)
                        {
                            final remote_ip = req.connectionInfo?.remoteAddress ?? InternetAddress("");

                            if (remote_ip.address == IPv4 && req.uri.path == "/" + secret_request)
                            {
                                req.response.write (secret_response);
                                req.response.close ();
                            }
                            else
                            {
                                req.response.write ("INVALID");
                                req.response.close ();
                            }
                        }
                    );
                }
            );
        }

        if (IPv6 != "INVALID")
        {
            log.info("IPv6 is   : $IPv6");

            HttpServer
                .bind (InternetAddress.anyIPv6, HTTP_IPv6_PORT)
                .then
            (
                (final server)
                {
                    http_server6 = server;

                    server.listen
                    (
                        (final HttpRequest req)
                        {
                            final remote_ip = req.connectionInfo?.remoteAddress ?? InternetAddress("");

                            if (remote_ip.address == IPv6 && req.uri.path == "/" + secret_request)
                            {
                                req.response.write (secret_response);
                                req.response.close ();
                            }
                            else
                            {
                                req.response.write ("INVALID");
                                req.response.close ();
                            }
                        }
                    );
                }
            );

            try
            {
                final open_bracket  = IPv6.contains(":") ? "[" : "";
                final close_bracket = IPv6.contains(":") ? "]" : "";

                final myself        = Uri.parse ("http://" + open_bracket + IPv6 + close_bracket + ":" + HTTP_IPv6_PORT.toString() + "/$secret_request");

                final response      = await http
                                        .get    (myself)
                                        .timeout (const Duration(seconds: 5),
                                            onTimeout: () {
                                                log.warning ("Self connect to IPv6 timedout");
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
                                                log.warning ("Self connect to IPv4 timedout");
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

                        j["HTTP_STATUS_CODE"] = response.statusCode;

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

    Future<bool> login (final String client_version) async
    {
        await init();
        await crypto.init();

        final p = "PublicKey : ${crypto.publicKey}".substring(0,20) + "...";

        log.info("Role      : $role");
        log.info(p);

        claims.forEach
        (
            (final k, final v)
            {
                if (! k.startsWith("//"))
                {
                    log.important("Claiming  : $k = $v");
                }
            }
        );

        final Map pre_login_body = {

                "proof_type"            : proof_type,
                "role"                  : role,
                "claims"                : claims,
                "projectName"           : projectName,
                "projectPublicKey"      : projectPublicKey,

                "keyType"               : crypto.keyType,
                "publicKey"             : crypto.publicKey,
                "walletPublicKey"       : crypto.walletPublicKey,

                "clientVersion"         : client_version,
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

        final Map r = await do_post (LOGIN_URL,login_body);

        if (r["result"] != null && r["result"]["success"] == true)
        {
            logged_in = true;
        }
        else
        {
            logged_in = false;
            log.error("Error : ${r}");
        }

        return logged_in;
    }

    Future<bool> logout () async
    {
        final Map body  = {};
        final Map r     = await do_post (LOGOUT_URL,body);

        if (r["result"] != null && r["result"]["success"] == true)
        {
            cookie      = "";
            logged_in   = false;
        }

        return (logged_in == false);
    }

    Future<void> run () async
    {
        if (cookie == "" || logged_in == false)
            throw Exception("Login did not succeed");

        do_run = true;

        while (do_run && payment_or_staking_required == false) // until user stops -OR- some exception occurs
        {
            await set_has_public_ip();

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

        log.info("$from : cleanup Proof");

        http_server4?.close(force:true);
        http_server6?.close(force:true);

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

        log.important("Done Running\n");
    }

    Future<void> run_websocket_IPv4 () async
    {
        if (! logged_in || websocket_IPv4_running)
            return;

        while (do_run && payment_or_staking_required == false) // until user stops -OR- some exception occurs
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
        if (IPv6 == "INVALID")
            return;

        if (! logged_in || websocket_IPv6_running)
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

        if (cookie == "" || logged_in == false)
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

        final ws                = WebSocketChannel (
                                        innerChannel,
                                        pingInterval    : EVERY_30_SECONDS,
                                        serverSide      : false
                                );

        connected_websockets [ip_version] = ws;

        log.success("Connected to WS : $ip_version");

        ws.stream.listen
        (
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

                    print("");

                    log.success("Got a challenge : $ip_version");

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

        if (ip_version == "IPv4" && has_public_IPv4)
        {
            final body = {
               "IPv4" : IPv4
            };

            await do_post (CLAIM_PUBLIC_IP_URL, body);
        }

        if (ip_version == "IPv6" && has_public_IPv6)
        {
            final body = {
               "IPv6" : IPv6
            };

            await do_post (CLAIM_PUBLIC_IP_URL, body);
        }

        await ws.sink.done.then((x)
        {
            log.error("WS closed : $ip_version");
        });

        try
        {
            client.close();
        }
        catch (e) { }

        return true;
    }

    Future<void> report_challenge_results (final ChallengeHandler ch) async
    {
        throw Exception("This is an abstract method!");
    }
}

class ChallengeHandler
{
    late Client                 client;

    Map                         challenge_info          = {};
    Map                         challenge_result        = {};

    String                      challenge_state         = "";

    bool                        init_done               = false;
    bool                        sent_challenge_results  = false;
    bool                        cleanup_done            = false;

    bool                        challenge_succeeded     = false;

    late String                 role;

    late LOG                    log;
    late LOG                    ws_log;

    late String                 challenge_id;
    late List<int>              challenge_id_in_ascii;

    late Duration               ntp_offset;

    late Crypto                 crypto;

    List whitelist              = [];

    int start_time              = -1;
    int end_time                = -1;

    bool is_IPv6_challenge      = false;

    InternetAddress             source_address4 = InternetAddress.anyIPv4;
    InternetAddress             source_address6 = InternetAddress.anyIPv6;

    late int                    source_port;
    late int                    destination_port;

    late RawDatagramSocket      socket;

    late DateTime               last_message_received_time;

    ChallengeHandler (this.role, this.crypto, this.challenge_info)
    {
        challenge_id            = this.challenge_info["challenge_id"] ?? "INVALID";
        challenge_id_in_ascii   = ascii.encode(this.challenge_id);
    }

    Future<bool> init () async
    {
        await crypto.init();

        ntp_offset = Duration (milliseconds : await ntp.NTP.getNtpOffset());

        log     = LOG("ChallengeHandler", set_client : client);
        ws_log  = LOG("WebSocket.Message",set_client : client);

        socket = await RawDatagramSocket.bind (

                is_IPv6_challenge   ? source_address6 : source_address4,
                source_port,
                reusePort           : ((role == "prover") && (! Platform.isWindows))

        );

        return true;
    }

    Future<bool> run () async
    {
        throw Exception("This is an abstract method!");
    }

    Future<void> cleanup (final String from) async
    {
        log.info("$from : sockets.close");

        try
        {
            socket.close();
        }
        catch (e) {}
    }

    bool send_UDP_message (final Map to, final String message_type, final Map message_map)
    {
        final   message     = jsonEncode(message_map).codeUnits;

        final   destination = to["ip"];
        final   dport       = to["udp_port"] ?? destination_port;

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
            final   int     timeout_in_milliseconds = MAX_UDP_MESSAGE_TIMEOUT,
            final   bool    is_IPv6_challenge       = false
        }
    ) async
    {
        final timeout = Now (ntp_offset)
                            .add (
                                  Duration (
                                    milliseconds : timeout_in_milliseconds
                                  )
                             ).microsecondsSinceEpoch;

        while (true)
        {
            final Datagram? datagram    = socket.receive();
            String          ip_version  = is_IPv6_challenge ? "IPv6" : "IPv4";

            if (datagram == null || datagram.data.length == 0 || datagram.data.length > UDP_CHUNK_SIZE)
            {
                final now = Now(ntp_offset).microsecondsSinceEpoch;

                if (now > timeout)
                {
                    log.error("Timeout for : $expected_message_types");
                    return {};
                }

                continue;
            }

            last_message_received_time = Now(ntp_offset);

            // if the user has specified a custom processMessageFunction, then process accordingly

            if (processMessageFunction != null)
                return await processMessageFunction(datagram.data);

            final sender_address    = datagram.address.address;
            final clean_address     = process_ip (sender_address);

            if (ip_version == "IPv6" && sender_address != clean_address)
            {
                ip_version = "IPv4";
            }

            final sender_ip         = (ip_version == "IPv6") ?
                                                    Uri.parseIPv6Address(clean_address):
                                                    Uri.parseIPv4Address(clean_address);

            // else process the message as a JSON

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

                if (signed_message["message"] == null)
                    return {};

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
            final bool verifySignature = true
        }
    ) async
    {
        Map signed_message = {};

        if (string_signed_message[0] != "{")
            return {};

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
}

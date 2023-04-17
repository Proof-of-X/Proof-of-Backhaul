import "dart:io";
import "dart:core";
import "dart:convert";

import "package:ntp/ntp.dart"                                   as ntp;
import "package:http/http.dart"                                 as http;
import "package:web_socket_channel/status.dart"                 as status;

import "package:stream_channel/stream_channel.dart";
import "package:web_socket_channel/web_socket_channel.dart";

import "log.dart";
import "constants.dart";
import "utils.dart";
import "crypto-factory.dart"                                    as cryptoFactory;

class Crypto
{
    String          keyType                 = "INVALID";
    String          publicKey               = "INVALID";
    Map             walletPublicKey         = {};
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

    bool            has_IPv6                = false;

    bool            websocket_IPv4_running  = false;
    bool            websocket_IPv6_running  = false;

    bool            in_a_challenge          = false;

    late ChallengeHandler           challenge_handler;

    bool            init_done               = false;

    late LOG log;
    late LOG ws_log;

    final Map connected_websockets          = {};

    HttpServer? http_server4                = null;
    HttpServer? http_server6                = null;

    bool    payment_or_staking_required     = false; // server expects some payment/staking

    bool logged_in                          = false;

    bool run_set_has_public_ip              = false;

    late Duration ntp_offset;


    Map config                              = {};
    Map claims                              = {};   // all things claimed by the client 

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
            try
            {
                final Map c = jsonDecode (
                    File(cf).readAsStringSync()
                );

                log.success("Read : $cf");

                c.forEach
                (
                    (final k, final v)
                    {
                        config[k] = v;
                        log.important("Considering : '$k' = '$v'");
                    }
                );
            }
            catch (e) {}
        }

        claims                  = config["claims"]          ?? claims;
        crypto.walletPublicKey  = config["walletPublicKey"] ?? {};

        if (ENV["WALLET_PUBLIC_KEY"] != null)
        {
            crypto.walletPublicKey = {
                crypto.keyType : ENV["WALLET_PUBLIC_KEY"]
            };
        }

        bool found_invalid_walletPublicKey = false;

        if (crypto.walletPublicKey.length == 0)
        {
            found_invalid_walletPublicKey = true;

            stdout.write("Could not find 'walletPublicKey' in '$role.json';\nplease enter it as keyType:walletPublicKey\nExample `solana:XYZ`");
            final input = stdin.readLineSync() ?? ":";

            final split = input.split(":");

            crypto.walletPublicKey = {
                split[0] : split[1]
            };
        }

        // walletPublicKey was found invalid -BUT- now looks like is valid

        if (found_invalid_walletPublicKey == true && crypto.walletPublicKey.length > 0)
        {
            try
            {
                log.info("Saving 'walletPublicKey' and 'claims' in '$role.json' ...");

                final f = await File(role + ".json").create();
                f.writeAsStringSync('{"walletPublicKey" : ${crypto.walletPublicKey}, "claims" : $claims}');

                log.success("Saved  'walletPublicKey' and 'claims' in '$role.json'");
            }
            catch (e) {}
        }

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
                log.info("Claiming : $k = $v");
            }
        );

        final Map pre_login_body = {
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

        await do_post (LOGIN_URL,login_body);

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

        log.info("$from : cleanup Proof");

        http_server4?.close(force:true);
        http_server6?.close(force:true);

        try
        {
            challenge_handler.cleanup("Proof.Client");
        }
        catch (e) {}

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

        await set_has_public_ip();

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
    late Client         client;

    Map                 challenge_info      = {};
    Map                 challenge_result    = {};

    late String         role;

    ChallengeHandler (this.role, this.challenge_info)
    {
        // nothing
    }

    Future<bool> init () async
    {
        throw Exception("This is an abstract method!");
    }

    Future<bool> run () async
    {
        throw Exception("This is an abstract method!");
    }

   Future<void> cleanup (final String from) async
    {
        throw Exception("This is an abstract method!");
    }
}

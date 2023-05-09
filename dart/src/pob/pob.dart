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

import "package:http/http.dart"                                 as http;

import "../common/log.dart";
import "../common/utils.dart";
import "../common/abc.dart"                                     as abc;

import "constants.dart";
import "../common/constants.dart";

class Client extends abc.Client
{
    Map args = {};

    Client (final String _role, final Map _args) : super ("pob", _role, _args)
    {
        args = _args;

        if (is_double(args,"bandwidth_claimed"))
                claims["bandwidth"] = args["bandwidth_claimed"];
    }

    Future<bool> init () async
    {
        if (init_done)
            return true;

        init_done = await super.init();

        log = LOG("pob.Client", set_client : this);

        if (! init_done)
            throw Exception("Could not initialize pob.Client");

        log.info("Version      : $POB_RELEASE_VERSION");

        if (is_double(config,"bandwidth_claimed"))
            claims["bandwidth"] = args["bandwidth_claimed"];

        if (role == "prover" || role == "challenger")
        {
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
        }

        return (init_done = true);
    }
}

class ChallengeHandler extends abc.ChallengeHandler
{
    Map<String,WebSocket>       challenge_websocket = {};
    late HttpServer             challenge_http_server;

    ChallengeHandler
    (
        final String        _role,
        final Map           _challenge_info,
        final abc.Crypto    _crypto,
        {
            InternetAddress?    setSourceAddress4   = null,
            InternetAddress?    setSourceAddress6   = null,
            int                 setSourcePort       = 0
        }
    ) : super (_role, _crypto, _challenge_info)
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

                        final WebSocket         socket    = await WebSocketTransformer.upgrade(request);
                        final InternetAddress   ip        = request.connectionInfo?.remoteAddress ?? InternetAddress("");

                        await socket.listen
                        (
                            (final message) async
                            {
                                await handle_challenge_message (message,ip,socket);
                            }
                        );

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

    Future<void> connect_to_self (final int port) async
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

    Future<void> start_websocket_client (final String host, final String publicKey) async
    {
        String host_with_brackets   = host.contains(":") ? "[" + host + "]" : host ;

        final port                  = role == "prover" ? CHALLENGER_PORT : PROVER_PORT;
        final challenge_id          = challenge_info["challenge_id"];

        final ws_url                = "ws://" + host_with_brackets + ":" + port.toString()  + "/ws?challenge_id=$challenge_id";

        for (int i = 1; i <= 10; ++i)
        {
            try
            {
                ws_log.important("Connecting to WebSocket of : $host ...");

                challenge_websocket[publicKey] = await WebSocket.connect(ws_url);

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

                await ws.listen
                (
                    (final message) async
                    {
                        await handle_challenge_message (message, InternetAddress(host), ws);
                    }
                );

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
        if (cleanup_done)
            return;

        await super.cleanup(from);

        try
        {
            challenge_http_server.close(force: true);
        }
        catch (e) {}

        cleanup_done            = true;
        client.in_a_challenge   = false;
    }
}

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

import "../common/log.dart";
import "../common/utils.dart";
import "../common/abc.dart"                                     as abc;

import "constants.dart";
import "../common/constants.dart";

class Client extends abc.Client
{
    Map args = {};

    Client (final String _role, final Map _args) : super ("pol", _role, _args)
    {
        args = _args;

        if (is_double(args,"latitude"))
                claims["latitude"] = args["latitude"];

        if (is_double(args,"longitude"))
                claims["longitude"] = args["longitude"];

        if (is_double(args,"radius"))
                claims["radius"] = args["radius"];

        if (is_string(args,"country"))
                claims["country"] = args["country"];

        if (is_string(args,"area"))
                claims["area"] = args["area"];

        if (is_string(args,"area"))
                claims["area"] = args["area"];
    }

    Future<bool> init () async
    {
        if (init_done)
            return true;

        init_done = await super.init();

        log = LOG("pol.Client", set_client : this);

        if (! init_done)
            throw Exception("Could not initialize pol.Client");

        return (init_done = true);
    }
}

class ChallengeHandler extends abc.ChallengeHandler
{
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
        source_port         = (role == "prover") ? PROVER_PORT      : CHALLENGER_PORT;
        destination_port    = (role == "prover") ? CHALLENGER_PORT  : PROVER_PORT;

        if (setSourceAddress4 != null)
            source_address4 = setSourceAddress4;

        if (setSourceAddress6 != null)
            source_address6 = setSourceAddress6;

        if (setSourcePort > 0)
            source_port = setSourcePort;
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

        cleanup_done            = true;
        client.in_a_challenge   = false;
    }
}

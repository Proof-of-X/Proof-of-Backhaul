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

import "abc.dart" as abc;

final level = {
    "INFO" : 0,
};

const Map colormap = {
    "\x1B[31m" : "🟥",
    "\x1B[32m" : "🟩",
    "\x1B[33m" : "🟧",
    "\x1B[34m" : "🟦",
    "\x1B[37m" : "⬜",
};

final config = {
   "pob.Client"                     : "INFO",
   "prover.Client"                  : "INFO",
   "challenger.Client"              : "INFO",

   "pob.ChallengeHandler"           : "INFO",
   "prover.ChallengeHandler"        : "INFO",
   "challenger.ChallengeHandler"    : "INFO",

   "pob.Crypto"                     : "INFO",
   "solana.Crypto"                  : "INFO",
   "ethereum.Crypto"                : "INFO",
};

class LOG
{
    String          name      = "";
    abc.Client?     client    = null;

    LOG (final String set_name, {final abc.Client? set_client = null})
    {
        name        = set_name;
        client      = set_client;
    }

    void info(final String message)
    {
        _log("\x1B[37m",message);
    }

    void error (final String message)
    {
        _log("\x1B[31m",message);
    }

    void warning (final String message)
    {
        _log("\x1B[33m",message);
    }

    void success (final String message)
    {
        _log("\x1B[32m",message);
    }

    void important (final String message)
    {
        _log("\x1B[34m",message);
    }

    void _log(final String color, final String message)
    {
        int min_log_level       = level[name]           ?? 0;
        int config_log_level    = level[config[name]]   ?? 0;

        final icon              = colormap[color] ?? "⬜";

        if (config_log_level >= min_log_level)
        {
            final now   = DateTime.now().toUtc();
            final time  = now.month.toString().padLeft(2,"0") + "/" + now.day.toString().padLeft(2,"0") + " " + now.hour.toString().padLeft(2,"0") + ":" + now.minute.toString().padLeft(2,"0");

            if (Platform.isAndroid || Platform.isIOS)
            {
               client?.Log (icon,message);
            }

            print("$time | ${name} | $color$message\x1B[0m");
        }
    }
}

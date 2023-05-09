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

import "../common/log.dart";

import "payer.dart"     as payer;
import "release.dart"   as release;

Future<void> run (final List<String> args) async
{
    String  keyType         = "solana";
    String  prover          = "INVALID";

    Map     walletPublicKey = {};

    if (args.length >= 1)
        prover              = args[0];

    if (args.length >= 2)
        keyType             = args[1];

    if (args.length >= 3)
        walletPublicKey     = {keyType : args[2]};

    final c = payer.Client ({
        "prover"            : prover,
        "keyType"           : keyType,
        "walletPublicKey"   : walletPublicKey
    });

    final log = LOG("Run.Payer", set_client : c);

    try
    {
            await c.login (release.version);

            if (c.payment_or_staking_required == true)
            {
                print("Press [ENTER] to quit");

                stdin.readLineSync();

                exit(-1); // manual intervention is required here
            }

            await c.run();
    }
    catch (e)
    {
        log.error("Exception : $e");

        await c.cleanup("Run.Payer");

        exit(-1);
    }

    exit(0);
}

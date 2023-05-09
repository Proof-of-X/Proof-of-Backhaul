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
import "dart:isolate";

import "run-prover-once.dart"       as prover;

import "../common/utils.dart";

import "constants.dart";
import "release.dart"               as release;

const client_key = "pol_prover_client";

void main(final List<String> args) async
{
    if (args.length == 1 && args[0] == '-v')
    {
        print("$POL_RELEASE_VERSION");
        exit(0);
    }

    final executable = Platform.executable;

    if (executable.endsWith(".exe"))
    {
        if (executable.contains("new--"))
        {
            final original_executable = executable.replaceAll("new--","");

            await File(executable).copy(original_executable);

            await Process.start (
                original_executable,
                args,
                mode : ProcessStartMode.detached
            );

            exit(0);
        }
        else
        {
            await update_client (client_key, release.version, LATEST_VERSION_PROVER_URL, args);
        }
    }

    while (true)
    {
        try
        {
            print("\n----- $client_key -----");

            await Isolate.run (
                () async
                {
                    await prover.run (args);
                }
            );

            print("=====");
        }
        catch (e)
        {
            print("Exception : $e");
        }

        await update_client (client_key, release.version, LATEST_VERSION_PROVER_URL, args);
    }
}

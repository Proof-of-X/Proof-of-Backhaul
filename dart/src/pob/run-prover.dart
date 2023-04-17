import "dart:io";
import "dart:isolate";

import "run-prover-once.dart"       as prover;

import "../common/utils.dart";

import "constants.dart";
import "release.dart"               as release;

const client_key = "pob_prover_client";

void main(final List<String> args) async
{
    if (args.length == 1 && args[0] == '-v')
    {
        print("$POB_RELEASE_VERSION");
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
            await update_client (client_key, release.version, args);
        }
    }

    while (true)
    {
        try
        {
            print("-----");

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

        await update_client (client_key, release.version, args);
    }
}

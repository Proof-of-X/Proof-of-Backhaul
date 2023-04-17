import "dart:io";

import "../common/log.dart";

import "constants.dart";
import "challenger.dart"    as challenger;
import "release.dart"       as release;

Future<void> run (List<String> args) async
{
    String  projectName      = "";
    String  projectPublicKey = "";
    String  keyType          = "";
    Map     walletPublicKey  = {};

    if (args.length >= 1)
        projectName         = args[0];

    if (args.length >= 2)
        keyType             = args[1];

    if (args.length >= 3)
        projectPublicKey    = args[2];

    if (args.length >= 4)
        walletPublicKey     = {keyType : args[3]};

    int num_consecutive_failures = 0;

    while (num_consecutive_failures < 10)
    {
        final c = challenger.Client ({
            "keyType"           : "solana",
            "projectName"       : projectName,
            "projectPublicKey"  : projectPublicKey,
            "walletPublicKey"   : walletPublicKey
        });

        final log = LOG("Run.Challenger", set_client : c);

        try
        {
            await c.login (release.version);

            if (c.payment_or_staking_required == true)
            {
                stdout.write("Press [ENTER] to quit");
                stdin.readLineSync();

                exit(-1); // manual intervention is required here
            }

            await c.run();

            if (c.logged_in == false)
                ++num_consecutive_failures;

            num_consecutive_failures = 0;
        }
        catch (e)
        {
            log.error("Exception : $e");
            await c.cleanup("Run.Challenger");

            ++num_consecutive_failures;
        }

        sleep (FOR_2_SECONDS);
    }
}

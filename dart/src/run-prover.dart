import "dart:io";

import "log.dart";
import "prover.dart" as prover;

import "constants.dart";

void main (List<String> args) async
{
    String projectName      = "";
    String projectPublicKey = "";
    String walletPublicKey  = "INVALID";

    if (args.length == 1 && args[0] == '-v')
    {
        print("$POB_RELEASE_VERSION");
        exit(0);
    }

    if (args.length >= 1)
        projectName         = args[0];

    if (args.length >= 2)
        projectPublicKey    = args[1];

    if (args.length >= 3)
        walletPublicKey     = args[2];

    int num_consecutive_failures = 0;

    while (num_consecutive_failures < 10)
    {
        final c = prover.Client ({
            "keyType"           : "solana",
            "bandwidth_claimed" : 10.0,
            "projectName"       : projectName,
            "projectPublicKey"  : projectPublicKey,
            "walletPublicKey"   : walletPublicKey
        });

        final log = LOG("Run.Prover", set_pob_client : c);

        try
        {
            await c.login();

            if (c.payment_or_staking_required == true)
            {
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
            await c.cleanup("Run.Prover");

            ++num_consecutive_failures;
        }

        sleep (FOR_2_SECONDS);
    }
}

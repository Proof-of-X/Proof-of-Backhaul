import "dart:io";

import "pob.dart" as pob;

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
   "filecoin.Crypto"                : "INFO",
};

class LOG
{
    String      name        = "";
    pob.Client? pob_client  = null;

    LOG (String set_name, {final pob.Client? set_pob_client = null})
    {
        name        = set_name;
        pob_client  = set_pob_client;
    }

    void info(String message)
    {
        _log("\x1B[37m",message);
    }

    void error (String message)
    {
        _log("\x1B[31m",message);
    }

    void warning (String message)
    {
        _log("\x1B[33m",message);
    }

    void success (String message)
    {
        _log("\x1B[32m",message);
    }

    void important (String message)
    {
        _log("\x1B[34m",message);
    }

    void _log(String color, String message)
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
                pob_client?.Log(icon,message);
            }

            print("$time | ${name} | $color$message\x1B[0m");
        }
    }
}

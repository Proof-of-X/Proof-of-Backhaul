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
import "dart:typed_data";

import "package:http/http.dart"                                 as http;
import "constants.dart";
import "log.dart";

bool is_string(final Map m, final String k)
{
    if (m.containsKey(k) && m[k] is String)
        return true;
    else
        return false;
}

bool is_double (final Map m, final String k)
{
    if (m.containsKey(k) && m[k] is double)
        return true;
    else
        return false;
}

bool is_bool(final Map m, final String k)
{
    if (m.containsKey(k) && m[k] is bool)
        return true;
    else
        return false;
}

bool is_list_equals (final List<int> a, final List<int> b)
{
    if (identical(a,b))
        return true;

    if (a.length != b.length)
        return false;

    for (int i = 0; i < a.length; i++)
    {
        if (a[i] != b[i])
            return false;
    }

    return true;
}

String process_ip (final String ip)
{
    if (ip.startsWith("::ffff:") && ip.contains("."))
        return ip.split("::ffff:")[1];
    else
        return ip;
}

Uint8List int32bytes (final int value)
{
    return Uint8List(4)..buffer.asUint32List()[0] = value;
}

Uint8List int8bytes (final int value)
{
    return Uint8List(1)..buffer.asUint8List()[0] = value;
}

DateTime Now (final Duration ntp_offset)
{
    return DateTime.now().add(ntp_offset).toUtc();
}

Future<void> update_client (
    final String        client_key,
    final String        running_version,
    final Uri           download_url,
    final List<String>  args
) async
{
    final log = LOG("Updates");

    if (! Platform.executable.endsWith(".exe"))
        return;

    print("\n----- $client_key -----");

    switch (client_key)
    {
        case "pob_prover_client":
        case "pob_challenger_client":
        {
            if (ENV["ENABLE_POB_UPDATES"] == null)
            {
                return log.warning("Updates are turned : OFF");
            }

            break;
        }

        case "pol_prover_client":
        case "pol_challenger_client":
        {
            if (ENV["ENABLE_POL_UPDATES"] == null)
            {
                return log.warning("Updates are turned : OFF");
            }

            break;
        }
    }

    log.success     ("Updates are turned : ON");
    log.important   ("Checking for latest version ...");

    await http
        .get    (LATEST_VERSION_URL)
        .then
    (
        (final version_response) async
        {
            if (version_response.statusCode != 200)
            {
                log.error("Server returned : `${version_response.statusCode}`. Cannot get latest version of client!");
                return;
            }

            final   split           = version_response.body.split("\n");
            String  latest_version  = "";

            try
            {
                for (final s in split)
                {
                    if (s.startsWith(client_key))
                    {
                        latest_version = s.split('"')[1];
                        break;
                    }
                }
            }
            catch (e) {}

            log.info("Current version is : '$running_version'");
            log.info("Latest  version is : '$latest_version'");

            final int_running_version   = int.parse(running_version);
            final int_latest_version    = int.parse(latest_version);

            if (int_running_version >= int_latest_version)
            {
                log.info("No new updates!");
                return;
            }

            log.info        ("Trying to update ...");
            log.important   ("Downloading : `$download_url`");

            await http
                    .get (download_url)
                    .then
            (
                (final response) async
                {
                    final split = Platform.executable.split("/");
                    final path  = split [split.length - 1];

                    if (response.statusCode != 200)
                    {
                        log.error("Server returned : `${response.statusCode}`. Cannot update!");
                        return;
                    }

                    final latest_executable = "./new--" + path;

                    await File(latest_executable).writeAsBytes(response.bodyBytes);

                    String downloaded_mbps = (response.bodyBytes.length/1024.0/1024.0)
                                                .toStringAsFixed(3);

                    log.success("Saved latest version at : `$latest_executable` ($downloaded_mbps MB)");

                    if (! Platform.isWindows)
                    {
                        try
                        {
                            await Process.run ("chmod", ["+x", latest_executable]);
                        }
                        catch (e) {}
                    }

                    // Test the new executable before updating

                    await Process.run (latest_executable, ['-v']).then
                    (
                        (final result) async
                        {
                            // should return a version in stdout and no stderr

                            if (result.stdout != "" || result.stderr == "")
                            {
                                log.important   ("Downloaded update with version : ${result.stdout}");
                                log.success     ("Update succeeded!");

                                await Process.start (
                                    latest_executable,
                                    args,
                                    mode        : ProcessStartMode.detachedWithStdio,
                                    runInShell  : true
                                );

                                exit(0);
                            }
                            else
                            {
                                log.error("Update failed!");
                                return;
                            }
                        }
                    );
                }
            );
        }
    );
}

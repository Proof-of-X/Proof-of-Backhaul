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

import "package:solana/solana.dart";
import "package:solana/base58.dart";

import "abc.dart"                       as abc;

final ENV = Platform.environment;

final String project_name           = "solana";
final String default_id_file_name   = "id.json";

class Crypto extends abc.Crypto
{
        Crypto (final Map args) : super ("solana", args)
        {
            if (keyPair != null)
            {
                final p     = keyPair.publicKey;
                publicKey   = p.toBase58();
            }
        }

        @override
        Future<bool> init() async
        {
            if (init_done)
                return true;

            if (keyPair != null && publicKey != "INVALID")
                return (init_done = true);     // keyPair was already initialized

            bool private_key_found = false;

            // If id_file is not initialized, set it
            if (id_file == "INVALID")
            {
                    String? home = ENV["HOME"] == null ? "." : ENV["HOME"];

                    if (home == null)
                        id_file = default_id_file_name;
                    else
                        id_file = home + "/.config/" + project_name + "/" + default_id_file_name;
            }

            String key_info_in_file = "";

            try
            {
                    key_info_in_file = File(id_file).readAsStringSync();
            }
            catch (e)
            {
                    try
                    {
                            // try in the current directory

                            key_info_in_file = File(default_id_file_name)
                                                    .readAsStringSync();
                    }
                    catch (e) {}
            }

            // Check if private key exists. If not, generate one and save it
            try
            {
                    if (key_info_in_file == "")
                            print("WARNING : Couldn't find 'id.json'");
                    else
                    {
                            final k = jsonDecode(key_info_in_file)
                                        .cast<int>()
                                        .sublist(0,32);

                            keyPair = await Ed25519HDKeyPair
                                                .fromPrivateKeyBytes (
                                                    privateKey : k
                                                );

                            private_key_found = true;
                    }
            }
            catch (e)
            {
                    print(e);
                    print("");

                    print("ERROR: $project_name's '$default_id_file_name' file has invalid data");

                    print("");
            }

            if (! private_key_found)
            {
                    print("Generating a new key ...");

                    keyPair = await Ed25519HDKeyPair.random();

                    await save_keyPair();
            }

            final p     = keyPair.publicKey;
            publicKey   = p.toBase58();

            return (init_done = true);
        }

        @override
        Future<String> sign (final String message) async
        {
            final List<int> bytes_message   = message.codeUnits;
            final           bytes_signature = await keyPair.sign(bytes_message);
            final String    signature       = base58encode (bytes_signature.bytes);

            return signature;
        }

        static Future<bool> verify (final String message, final String signature, String public_key) async
        {
            List<int> bytes_message     = message.codeUnits;
            List<int> bytes_signature   = base58decode(signature);

            Ed25519HDPublicKey pk = Ed25519HDPublicKey.fromBase58(public_key);

            return await verifySignature (
                   message     : bytes_message,
                   signature   : bytes_signature,
                   publicKey   : pk
            );
        }

        static Future<int> signature_length_in_bytes () async
        {
            return 64;
        }

        static Future<int> publickey_length_in_bytes () async
        {
            return 64;
        }

        @override
        Future<bool> save_keyPair () async
        {
                File? f = null;

                try
                {
                        f = await File(id_file)
                                        .create(recursive:true);
                }
                catch (e)
                {
                        id_file = default_id_file_name; // in the current directory

                        try
                        {
                                f = await File(id_file)
                                                .create(recursive:true);
                        }
                        catch (e) {}
                }

                if (f == null)
                {
                        print("WARNING : Couldn't save the key");
                        return false;
                }
                else
                {
                    final sk = await keyPair.extract();
                    final pk = await keyPair.extractPublicKey();

                    final k                         = sk.bytes + pk.bytes;
                    final String key_info_in_file   = k.toString();

                    f.writeAsStringSync (key_info_in_file);

                    print("Saved $project_name key @ $id_file");
                }

                return true;
        }
}

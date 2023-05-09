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
import 'dart:math';
import 'dart:typed_data';

import "package:web3dart/crypto.dart";
import "package:eth_sig_util/eth_sig_util.dart";
import "package:web3dart/web3dart.dart";

import "abc.dart"                   as abc;

final ENV = Platform.environment;

final String default_id_file_name = "ethereum_fc_id.json";

class Crypto extends abc.Crypto
{
        String evm_name = "INVALID";

        Crypto(final Map args) : super("ethereum", args)
        {
            if (keyPair != null)
            {
                publicKey   = get_public_key();
            }

            evm_name = args["evm_name"] ?? evm_name;
        }

        @override
        Future<bool> init() async
        {
            if (init_done)
                return true;

            if (keyPair != null && publicKey != "INVALID")
                return (init_done = true);     // keyPair was already initialized

            bool private_key_found = false;

            //// If id_file is not initialized, set it
            if (id_file == "INVALID") {

                    String? home = ENV["HOME"] == null ? "." : ENV["HOME"];

                    if (home == null)
                        id_file = default_id_file_name;
                    else
                        id_file = home + "/.config/" + evm_name + "/"
                                                            + default_id_file_name;
            }

            //// Read contents of the id_file
            try
            {
                    print("Reading Keypair from file");

                    String key_info_in_file = bytesToHex(File(id_file).readAsBytesSync());


                    print("Read Keypair from file $key_info_in_file");

                    /*final k = jsonDecode(key_info_in_file)
                                        .cast<int>()
                                        .sublist(0,32); */

                    keyPair = EthPrivateKey.fromHex(key_info_in_file);

                    print(keyPair);

                    //keyPair = PrivateKey.fromBytes(getSecp256k1(), k);

                    private_key_found = true;

                    if (await _sign_and_verify() == true)
                    {
                        print ("Verification success");
                        return true;
                    }
                    else
                    {
                        print ("Verification fail");
                        return false;
                    }

            }
            catch (e)
            {       print(e);
                    print("WARNING : Couldn't find $id_file");
            }

            // Check if private key exists. If not, generate one and save it
            if (!private_key_found) {

                    print("Generating a new key ...");

                    /*

                    final ec_function             = getSecp256k1();
                    keyPair                     = ec_function.generatePrivateKey();
                    */
                    final rng = Random.secure();
                    keyPair = EthPrivateKey.createRandom(rng);
                    print("Pivate key is ${keyPair.privateKey}");

                    if (await _sign_and_verify() == true)
                    {
                        //// Save keyPair to file
                        bool is_key_pair_saved = await save_keyPair ();

                        if (is_key_pair_saved == false){
                            return false;
                        }

                    }
                    else
                    {
                        return false;
                    }
            }
            publicKey     = get_public_key();

            print ("Generated Public key is $publicKey");

            return (init_done = true);
        }

        String get_public_key () {

            return keyPair.address.hex;

        }

        Future<bool> _sign_and_verify () async
        {
                String validation_message   = "Hello world" ;
                bool is_verified = false;

                try
                {
                    String signed_message       = await
                                                    sign(validation_message);

                    is_verified                 = await
                                                    verify
                                                        (   validation_message,
                                                            signed_message,
                                                            get_public_key()
                                                        );
                    print("Verified is $is_verified");

                } catch (e) {

                    print("Verified is $is_verified");
                    return false;
                }

                return is_verified;
        }

        @override
        Future<String> sign (final String message) async
        {
            //Credentials fromHex = EthPrivateKey.fromHex(keyPair.toHex());

            Uint8List signed_message = keyPair
                                        .signPersonalMessageToUint8List
                                                (
                                                    Uint8List.fromList(
                                                        message.codeUnits)
                                                );

            print("Signed message is ${'0x'+bytesToHex(signed_message) }");

            return '0x'+bytesToHex(signed_message);
        }

        static Future<bool> verify (final String message,
                                    final String signature,
                                    String public_key) async
        {
            String recovered_public_key = '';

            try {

                    recovered_public_key
                            =
                            EthSigUtil
                                .recoverPersonalSignature
                                    (
                                        signature: signature,
                                        message: Uint8List.fromList(message.codeUnits)
                                    );

                            print ("Recovered public key is $recovered_public_key");
                }
            catch (e)
                {
                    return false;
                }

            if (recovered_public_key == public_key)
                {
                    return true;
                }
            else
                {
                    return false;
                }

        }


        static Future<int> signature_length_in_bytes () async
        {
            return 64; // XXX to be verified
        }

        static Future<int> publickey_length_in_bytes () async
        {
            return 64; // XXX to be verified
        }


        @override
        Future<bool> save_keyPair () async
            {
                    File? f = null;

                    print("Saving keyPair");

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
                            catch (e) {
                                    print("WARNING : Couldn't create the file");
                            }
                    }

                    if (f == null)
                    {
                            print("WARNING : Couldn't save the key");
                            return false;
                    }
                    else
                    {
                            //final sk        = keyPair.toHex().codeUnits;
                            //final pk        = get_public_key().codeUnits;
                            //final k         = sk + pk;
                            //final String keys_to_file   = keyPair.privateKey;
                            //print("While writing $keys_to_file");
                            f.writeAsBytesSync(keyPair.privateKey);
                            return true;
                    }
            }
}

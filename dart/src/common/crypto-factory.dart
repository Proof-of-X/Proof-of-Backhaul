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

import "abc.dart"           as abc;
import "solana.dart"        as solana;
import "ethereum.dart"      as ethereum;

enum CryptoAlgo
{
    ETHEREUM,
    FILECOIN,
    SOLANA,
}

final CRYPTO_ALGO_ETHEREUM  = CryptoAlgo.ETHEREUM.index;
final CRYPTO_ALGO_FILECOIN  = CryptoAlgo.FILECOIN.index;
final CRYPTO_ALGO_SOLANA    = CryptoAlgo.SOLANA.index;

final CRYPTO_KEY_TYPE = {
    "ethereum"  : CRYPTO_ALGO_ETHEREUM,
    "filecoin"  : CRYPTO_ALGO_FILECOIN,
    "solana"    : CRYPTO_ALGO_SOLANA,
};

abc.Crypto create(final Map args)
{
    final String keyType = args["keyType"];

    switch (keyType)
    {
        case "ethereum":
            args["evm_name"] = "ethereum";
            return ethereum.Crypto(args);

        case "filecoin":
            args["evm_name"] = "filecoin";
            return ethereum.Crypto(args);

        case "solana":
            return solana.Crypto(args);

        default:
            throw Exception("Cannot find the crypto $keyType");
    }
}

Future<bool> verify(final Map signed_message) async
{
    final message   = signed_message["message"];
    final keyType   = signed_message["keyType"];
    final publicKey = signed_message["publicKey"];
    final signature = signed_message["signature"];

    switch (keyType)
    {
        case "ethereum":
            return await ethereum.Crypto.verify (message, signature, publicKey);

        case "filecoin":
            return await ethereum.Crypto.verify (message, signature, publicKey);

        case "solana":
            return await solana.Crypto.verify   (message, signature, publicKey);

        default:
            throw Exception("Cannot find the crypto $keyType");
    }
}

Future<int> signature_length_in_bytes (String keyType) async
{
    switch (keyType)
    {
        case "ethereum":
            return await ethereum.Crypto.signature_length_in_bytes();

        case "filecoin":
            return await ethereum.Crypto.signature_length_in_bytes();

        case "solana":
            return await solana.Crypto.signature_length_in_bytes();

        default:
            throw Exception("Cannot find the crypto $keyType");
    }
}

Future<int> publickey_length_in_bytes (String keyType) async
{
    switch (keyType)
    {
        case "ethereum":
            return await ethereum.Crypto.publickey_length_in_bytes();

        case "filecoin":
            return await ethereum.Crypto.publickey_length_in_bytes();

        case "solana":
            return await solana.Crypto.publickey_length_in_bytes();

        default:
            throw Exception("Cannot find the crypto $keyType");
    }
}

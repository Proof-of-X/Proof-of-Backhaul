import "pob.dart"           as pob;
import "solana.dart"        as solana;
import "filecoin.dart"      as filecoin;

enum CryptoAlgo
{
    SOLANA,
    FILECOIN
}

final CRYPTO_ALGO_SOLANA    = CryptoAlgo.SOLANA.index;
final CRYPTO_ALGO_FILECOIN  = CryptoAlgo.FILECOIN.index;

final CRYPTO_KEY_TYPE = {
    "solana"    : CRYPTO_ALGO_SOLANA,
    "filecoin"  : CRYPTO_ALGO_FILECOIN,
};

pob.Crypto create(final Map args)
{
    final String keyType = args["keyType"];

    switch (keyType)
    {
        case "filecoin":
            return filecoin.Crypto(args);

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
        case "filecoin":
            return await filecoin.Crypto.verify (message, signature, publicKey);

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
        case "filecoin":
            return await filecoin.Crypto.signature_length_in_bytes();

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
        case "filecoin":
            return await filecoin.Crypto.publickey_length_in_bytes();

        case "solana":
            return await solana.Crypto.publickey_length_in_bytes();

        default:
            throw Exception("Cannot find the crypto $keyType");
    }
}

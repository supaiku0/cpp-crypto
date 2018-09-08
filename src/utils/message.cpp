/**
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#include "utils/message.h"
#include <iostream>

/**
 * Sign a message using the given passphrase.
 *
 * @param string $message
 * @param string $passphrase
 *
 * @return \ArkEcosystem\Crypto\Message
 **/
void Ark::Crypto::Utils::Message::sign(
        std::string newMessage,
        const char *const passphrase
) {
    this->message = newMessage;

    /* Get the PrivateKey */
    PrivateKey privateKey = Ark::Crypto::Identities::PrivateKey::fromPassphrase(passphrase);

    /* Set the PublicKey from the derived PrivateKey */
    this->publicKey = Ark::Crypto::Identities::PublicKey::fromPrivateKey(privateKey);

    /* Get the Hash */
    const auto unsignedMessage = reinterpret_cast<const unsigned char*>(message.c_str());
    const auto hash = Sha256::getHash(unsignedMessage, this->message.length());

    /* Sign it */
    cryptoSign(hash, privateKey, this->signature);
};
/**/

/**
 * @brief Verify the message contents.
 *
 * @return bool
 **/
bool Ark::Crypto::Utils::Message::verify()
{
    /* Get the Uncompressed PublicKey */
    auto publicKeyBytes = this->publicKey.toBytes(); // compressed publicKey bytes (uint8_t*)
    uint8_t uncompressedPublicKey[64] = {}; // create uncompressed publicKey buffer (uint8_t[64])
    const struct uECC_Curve_t * curve = uECC_secp256k1(); // define the curve-type
    uECC_decompress(publicKeyBytes, uncompressedPublicKey, curve); // decompress the key
    if (uECC_valid_public_key(uncompressedPublicKey, curve) == 0) { return 0; }; // validate the uncompressed publicKey

    /* Split uncompressed publicKey into (x,y) coordinate buffers */
    char xBuffer[65] =  "\0";
    char yBuffer[65] =  "\0";
    for (int i = 0; i < 32; i++)  {
        snprintf(&xBuffer[i*2], 64, "%02x", uncompressedPublicKey[i]);
        snprintf(&yBuffer[i*2], 64, "%02x", uncompressedPublicKey[i + 32]);
    };

    /* Create curvepoint of uncompressed publicKey(x,y) */
    FieldInt x(xBuffer); // convert xBuffer to FieldInteger
    FieldInt y(yBuffer); // convert yBuffer to FieldInteger
    CurvePoint curvePoint(x, y); //

    /* Get SHA256 hash of (const unsigned char*)-casted message */
    const auto unsignedMessage = reinterpret_cast<const unsigned char*>(this->message.c_str()); // cast message to unsigned char*
    const auto hash = Sha256::getHash(unsignedMessage, this->message.length());

    /* Create curvepoint of uncompressed publicKey(x,y) */
    auto sig = ParseHex(HexStr(this->signature).c_str()); // get bytes of signature
    std::vector<uint8_t> r; // create r-value buffer
    std::vector<uint8_t> s; // create s-value buffer
    decodeDER(sig, r, s); // decode signature from DER into r & s buffers

    Uint256 r256(r.data()); // create Uint256/BigNumber from r-value buffer
    Uint256 s256(s.data()); // create Uint256/BigNumber from s-value buffer

    /* Verify */
    return Ecdsa::verify(
        curvePoint,
        hash,
        r256,
        s256
    );
};
/**/

/**
 * @brief Convert the message to its array representation using an array of pairs
 *
 * ' messageArray[0].first: "publickey" '
 * ' messageArray[0].second: uint8_t* (ex: { 2, 159, 223 ... 253, 151, 180 })
    };) '
 *
 * @return std::vector< std::pair<const char*, const uint8_t*> >
 **/
std::vector<std::pair<const char*, const uint8_t*>> Ark::Crypto::Utils::Message::toArray()
{
    return {
        { "publickey", this->publicKey.toBytes() },
        { "signature", this->signature.data() },
        { "message",  reinterpret_cast<const unsigned char*>(this->message.c_str()) }
    };
};
/**/

/**
 * @brief Convert the message to its JSON representation.
 *
 * @return std::string
 **/
std::string Ark::Crypto::Utils::Message::toJson()
{
    const auto messageArray = this->toArray();

    std::string messageJsonString;
    messageJsonString += "{\"";
    messageJsonString += messageArray[0].first;
    messageJsonString += "\":\"";

    messageJsonString += PublicKey(messageArray[0].second).c_str();

    messageJsonString += "\",\"";
    messageJsonString += messageArray[1].first;
    messageJsonString += "\":\"";

    messageJsonString += HexStr(
            &messageArray[1].second[0],
            &messageArray[1].second[0]
            + messageArray[1].second[1] + 2 // ecdsa DER-encoded signature size is always byte[1] + 2
    ).c_str();

    messageJsonString += "\",\"";
    messageJsonString += messageArray[2].first;
    messageJsonString += "\":\"";

    messageJsonString += reinterpret_cast<const char*>(messageArray[2].second);

    messageJsonString += "\"}";

    return messageJsonString;
}
/**/

/**
 * @brief Convert the message to its String representation.
 *
 * @return std::string
 **/
std::string Ark::Crypto::Utils::Message::toString()
{
    return this->toJson();
};
/**/

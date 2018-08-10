/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#include "identities/publickey.h"

/**************************************************
 * 
 **************************************************/
Ark::Crypto::Identities::PublicKey::PublicKey(const char *const newPublicKeyStr)
{ 
    (Ark::Crypto::Identities::PublicKey::validate(newPublicKeyStr))
        ? void(setBytes(&ParseHex(newPublicKeyStr).data()[0]))
        : void(this->bytes_[COMPRESSED_PUBLICKEY_SIZE - 1] = { '\0' });     
};
/*************************************************/

/**************************************************
 * 
 **************************************************/
Ark::Crypto::Identities::PublicKey::PublicKey(const uint8_t *newPublicKeyBytes)
{ 
    (PublicKey::validate(newPublicKeyBytes))
        ? void(setBytes(newPublicKeyBytes))
        : void(this->bytes_[COMPRESSED_PUBLICKEY_SIZE - 1] = { '\0' });
};
/*************************************************/

/**************************************************
 * 
 **************************************************/
void Ark::Crypto::Identities::PublicKey::setBytes(const uint8_t *newBytes)
{
    std::memmove(this->bytes_, newBytes, COMPRESSED_PUBLICKEY_SIZE);
};
/*************************************************/

/**************************************************
 * 
 **************************************************/
const uint8_t *Ark::Crypto::Identities::PublicKey::getBytes() { return this->bytes_; };
/*************************************************/

/**************************************************
 * 
 **************************************************/
bool Ark::Crypto::Identities::PublicKey::isValid() { return PublicKey::validate(*this); };
/*************************************************/

/**************************************************
 * 
 **************************************************/
const char* Ark::Crypto::Identities::PublicKey::c_str() const
{
    return BytesToHex(this->bytes_, &this->bytes_[0] + COMPRESSED_PUBLICKEY_SIZE).c_str();
};
/*************************************************/

/**************************************************
 * @brief Derive the public from the given passphrase.
 *
 * @param const char *const passphrase
 *
 * @return std::string
 **************************************************/
Ark::Crypto::Identities::PublicKey Ark::Crypto::Identities::PublicKey::fromPassphrase(const char *const passphrase)
{
    PrivateKey privateKey = PrivateKey::fromPassphrase(passphrase);
    return PublicKey::fromPrivateKey(privateKey);
};
/*************************************************/

/**************************************************
 * 
 **************************************************/
Ark::Crypto::Identities::PublicKey Ark::Crypto::Identities::PublicKey::fromPrivateKey(PrivateKey privateKey)
{
    std::vector<uint8_t> publicKey(COMPRESSED_PUBLICKEY_SIZE);
    const struct uECC_Curve_t * curve = uECC_secp256k1();
    uint8_t pub[64] = {};
    // TODO: using the current uECC implementation, a private key value of "1" will return a false negative.  
    // It appears to be not supported given the following issue: https://github.com/kmackay/micro-ecc/issues/128
    const uint8_t *privkeyBytes = privateKey.getBytes();
    auto ret = uECC_compute_public_key(&privkeyBytes[0], pub, curve);  // Don't check the return inline with the assert.  MSVC optimizer does bad things.
    assert(ret != 0);
    assert(publicKey.size() == COMPRESSED_PUBLICKEY_SIZE);
    uECC_compress(pub, &publicKey[0], curve);
    return { BytesToHex(&publicKey[0], &publicKey[0] + COMPRESSED_PUBLICKEY_SIZE).c_str() };
};
/*************************************************/

/**************************************************
 * @brief Create a public key instance from a hex string.
 *
 * @param const char *const publicKey
 *
 * @return PublicKey
 **************************************************/
Ark::Crypto::Identities::PublicKey Ark::Crypto::Identities::PublicKey::fromHex(const char *const publicKey) { return { publicKey }; };
/*************************************************/

/**************************************************
 * @brief Validate the given public key.
 *
 * @param const char *const publicKey
 *
 * @return bool
 *************************************************/
bool Ark::Crypto::Identities::PublicKey::validate(const char *publicKeyStr)
{
    return ((std::strlen(publicKeyStr)/2) == COMPRESSED_PUBLICKEY_SIZE); // check length
};
/*************************************************/

/**************************************************
 * @brief Validate the given public key.
 *
 * @param PublicKey publicKey
 *
 * @return bool
 *************************************************/
bool Ark::Crypto::Identities::PublicKey::validate(PublicKey publicKey) { return PublicKey::validate(publicKey.c_str()); };
/*************************************************/

/**************************************************
 * @brief Validate the given public key.
 *
 * @param const uint8_t *publicKeyBytes
 *
 * @return bool
 *************************************************/
bool Ark::Crypto::Identities::PublicKey::validate(const uint8_t *publicKeyBytes)
{
    return validate(
            BytesToHex(
                publicKeyBytes,
                publicKeyBytes + COMPRESSED_PUBLICKEY_SIZE
            ).c_str()
    );
};
/*************************************************/

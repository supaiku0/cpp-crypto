/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#include "identities/privatekey.h"

/**************************************************
 * 
 **************************************************/
Ark::Crypto::Identities::PrivateKey::PrivateKey(const char *const newPrivateKeyStr)
{ 
    (PrivateKey::validate(newPrivateKeyStr))
        ? void(setBytes(&ParseHex(newPrivateKeyStr).data()[0]))
        : void(this->bytes_[PRIVATEKEY_SIZE - 1] = { '\0' });     
};
/*************************************************/

/**************************************************
 * 
 **************************************************/
Ark::Crypto::Identities::PrivateKey::PrivateKey(const uint8_t *newPrivateKeyBytes)
{ 
    (PrivateKey::validate(newPrivateKeyBytes))
        ? void(setBytes(newPrivateKeyBytes))
        : void(this->bytes_[PRIVATEKEY_SIZE - 1] = { '\0' });
};
/*************************************************/

/**************************************************
 * 
 **************************************************/
void Ark::Crypto::Identities::PrivateKey::setBytes(const uint8_t *newBytes)
{
    std::memmove(this->bytes_, newBytes, PRIVATEKEY_SIZE);
};
/*************************************************/

/**************************************************
 * 
 **************************************************/
const uint8_t *Ark::Crypto::Identities::PrivateKey::getBytes() { return this->bytes_; };
/*************************************************/

/**************************************************
 * 
 **************************************************/
const char* Ark::Crypto::Identities::PrivateKey::c_str() const
{
    return BytesToHex(this->bytes_, this->bytes_ + PRIVATEKEY_SIZE).c_str();
};
/*************************************************/

/**************************************************
 * @brief Derive the private key for the given passphrase.
 *
 * @param const char* const passphrase
 *
 * @return std::string
 **************************************************/
Ark::Crypto::Identities::PrivateKey Ark::Crypto::Identities::PrivateKey::fromPassphrase(const char* const passphrase)
{    
    std::vector<uint8_t> privateKey(PRIVATEKEY_SIZE);
    auto hash = Sha256::getHash(reinterpret_cast<const unsigned char*>(passphrase), std::strlen(passphrase));
    std::memcpy(&privateKey[0], hash.value, privateKey.size());
    return { BytesToHex(&privateKey[0], &privateKey[0] + PRIVATEKEY_SIZE).c_str() };
};
/*************************************************/

/**************************************************
 * @brief Create a private key instance from a hex string.
 *
 * @param const char *const privateKey
 *
 * @return PrivateKey
 **************************************************/
Ark::Crypto::Identities::PrivateKey Ark::Crypto::Identities::PrivateKey::fromHex(const char *const privateKey) { return { privateKey }; };
/*************************************************/

/**************************************************
 * @brief Derive the private key for the given WIF.
 *
 * @param const char* wifStr
 * @param uint8_t wifByte
 *
 * @return PrivateKey
 **************************************************/
Ark::Crypto::Identities::PrivateKey Ark::Crypto::Identities::PrivateKey::fromWIFString(const char* wifStr, uint8_t wifByte)
{
    Uint256 bigNum;
    bool compressed = true;
    auto ret = Base58Check::privateKeyFromBase58Check(wifStr, bigNum, &wifByte, compressed);
    assert(ret);
    std::vector<uint8_t> privateKey(PRIVATEKEY_SIZE);
    bigNum.getBigEndianBytes(&privateKey[0]);
    return { BytesToHex(&privateKey[0], &privateKey[0] + PRIVATEKEY_SIZE).c_str() };
};
/*************************************************/

/**************************************************
 * @brief Validate the given private key.
 *
 * @param const char *const privateKey
 *
 * @return bool
 *************************************************/
bool Ark::Crypto::Identities::PrivateKey::validate(const char *privateKeyStr)
{
    return ((std::strlen(privateKeyStr)/2) == PRIVATEKEY_SIZE); // check length
};
/*************************************************/

/**************************************************
 * @brief Validate the given private key.
 *
 * @param PrivateKey privateKey
 *
 * @return bool
 *************************************************/
bool Ark::Crypto::Identities::PrivateKey::validate(PrivateKey privateKey) { return PrivateKey::validate(privateKey.c_str()); };
/*************************************************/

/**************************************************
 * @brief Validate the given private key.
 *
 * @param const uint8_t *privateKeyBytes
 *
 * @return bool
 *************************************************/
bool Ark::Crypto::Identities::PrivateKey::validate(const uint8_t *privateKeyBytes)
{
    return validate(
            BytesToHex(
                privateKeyBytes,
                privateKeyBytes + PRIVATEKEY_SIZE
            ).c_str()
    );
};
/*************************************************/

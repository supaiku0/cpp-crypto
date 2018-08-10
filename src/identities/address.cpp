/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#include "identities/address.h"

/************************************************** 
 * @brief: constructor
 * 
 * @param: const char *const newAddressStr
 **************************************************/
Ark::Crypto::Identities::Address::Address(const char *const newAddressStr)
{ 
    (std::strlen(newAddressStr) == ADDRESS_LENGTH)
        ? void(setBytes(reinterpret_cast<const unsigned char*>(newAddressStr)))
        : void(this->bytes_[COMPRESSED_PUBLICKEY_SIZE] = { '\0' });    
};
/*************************************************/

/*************************************************/
// const bool isValid() { return Address::validate(*this); };
/*************************************************/

/************************************************** 
 * @brief: set bytes of Address
 * 
 * @param: const uint8_t *newBytes
 **************************************************/
void Ark::Crypto::Identities::Address::setBytes(const uint8_t *newBytes)
{
    std::memmove(this->bytes_, newBytes, ADDRESS_LENGTH);
};
/*************************************************/

/************************************************** 
 * @brief: returns bytes of Address
 * 
 * @return const uint8_t
 **************************************************/
const uint8_t *Ark::Crypto::Identities::Address::getBytes()
{
    return this->bytes_;
};
/*************************************************/

/**************************************************
 * @brief: returns cstring representation of stored bytes
 **************************************************/
const char* Ark::Crypto::Identities::Address::c_str() const
{
    return std::string(
        this->bytes_,
        this->bytes_ + ADDRESS_LENGTH
    ).c_str();
};
/*************************************************/

/**************************************************
 * @brief Derive the address from the given passphrase.
 *
 * @param const char* const passphrase
 * @param uint8_t networkVersion
 *
 * @return Address
 **************************************************/
Ark::Crypto::Identities::Address Ark::Crypto::Identities::Address::fromPassphrase(
        const char* const passphrase,
        uint8_t networkVersion
) {
    PublicKey publicKey = PublicKey::fromPassphrase(passphrase);
    return fromPublicKey(publicKey, networkVersion);
};
/*************************************************/

/**************************************************
 * @brief Derive the address from the given public key.
 *
 * @param PublicKey publicKey
 * @param uint8_t networkVersion
 *
 * @return Address
 **************************************************/
Ark::Crypto::Identities::Address Ark::Crypto::Identities::Address::fromPublicKey(
    PublicKey publicKey,
    uint8_t networkVersion
) {
    std::vector<uint8_t> seed(Ripemd160::HASH_LEN);
    Ripemd160::getHash(publicKey.getBytes(), COMPRESSED_PUBLICKEY_SIZE, &seed[0]);
    std::string s(35, '\0');
    Base58Check::pubkeyHashToBase58Check(&seed[0], networkVersion, &s[0]);    
    return { s.c_str() };
};
/*************************************************/

/**************************************************
 * @brief Derive the address from the given private key.
 *
 * @param PrivateKey privateKey
 * @param uint8_t networkVersion
 *
 * @return Address
 **************************************************/
Ark::Crypto::Identities::Address Ark::Crypto::Identities::Address::fromPrivateKey(
        PrivateKey privateKey,
        uint8_t networkVersion
) {
    PublicKey publicKey = PublicKey::fromPrivateKey(privateKey);
    return fromPublicKey(publicKey, networkVersion);
};
/*************************************************/

/************************************************** 
 * @brief Validate the given address.
 *
 * @param Address address
 * @param uint8_t networkVersion
 *
 * @return bool
 **************************************************/
bool Ark::Crypto::Identities::Address::validate(Address address, uint8_t networkVersion)
{
    std::uint8_t pub_key_hash[Ripemd160::HASH_LEN] = {};
    uint8_t version = 0;
    Base58Check::pubkeyHashFromBase58Check(address.c_str(), pub_key_hash, &version);
    return version == networkVersion;
};
/*************************************************/

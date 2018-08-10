/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#include "identities/wif.h"

/**************************************************
 * 
 **************************************************/
Ark::Crypto::Identities::WIF::WIF(const char *const newWIFStr)
{ 
    (std::strlen(newWIFStr) == WIF_SIZE)
        ? void(setBytes(reinterpret_cast<const unsigned char*>(newWIFStr)))
        : void(this->bytes_[WIF_SIZE - 1] = { '\0' });   
};
/*************************************************/

/**************************************************
 * 
 **************************************************/
Ark::Crypto::Identities::WIF::WIF(const uint8_t *newWIFBytes)
{
    setBytes(newWIFBytes);
};
/*************************************************/

/**************************************************
 * 
 **************************************************/
void Ark::Crypto::Identities::WIF::setBytes(const uint8_t *newBytes)
{
    std::memmove(this->bytes_, newBytes, WIF_SIZE);
};
/*************************************************/

/**************************************************
 * 
 **************************************************/
const uint8_t* Ark::Crypto::Identities::WIF::getBytes() { return this->bytes_; };
/*************************************************/

/**************************************************
 * 
 **************************************************/
const char* Ark::Crypto::Identities::WIF::c_str() const
{
    return std::string(
        this->bytes_,
        this->bytes_ + WIF_SIZE
    ).c_str();
};
/*************************************************/

/**************************************************
 * @brief Derive the WIF from the given passphrase.
 *
 * @param const char *const passphrase
 * @param uint8_t wifByte
 *
 * @return WIF
 **************************************************/
Ark::Crypto::Identities::WIF Ark::Crypto::Identities::WIF::fromPassphrase(
        const char *const passphrase,
        uint8_t wifByte
) {
    PrivateKey privateKey = PrivateKey::fromPassphrase(passphrase);
    std::string wifStr(53, '\0');
    Base58Check::privateKeyToBase58Check(
        Uint256(privateKey.c_str()),
        wifByte,
        true,
        &wifStr[0]
    );
    return { wifStr.c_str() };
};
/*************************************************/

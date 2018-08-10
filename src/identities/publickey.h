/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#ifndef PUBLICKEY_H
#define PUBLICKEY_H

#include "identities/encoding.h"
#include "identities/privatekey.h"

#include <cassert>
#include <cstring>

// #if defined(USE_IOT)
	#include "uECC.h"
// #else
// 	#include "../include/uECC/uECC.h"
// #endif

namespace Ark {
namespace Crypto {
namespace Identities {

/**************************************************
 * This is the public key class.
 *
 * @author Simon Downey <simon@ark.io>
 **************************************************/
class PublicKey
{
	protected:
		uint8_t bytes_[COMPRESSED_PUBLICKEY_SIZE];

    public:
    	PublicKey() : bytes_() {};
        PublicKey(const char *const newPublicKeyStr);
        PublicKey(const uint8_t *newPublicKeyBytes);

        void setBytes(const uint8_t *newBytes);
        const uint8_t *getBytes();

        bool isValid();
        const char* c_str() const;

        static PublicKey fromPassphrase(const char *const passphrase);
        static PublicKey fromPrivateKey(PrivateKey privateKey);
        static PublicKey fromHex(const char *const publicKey);
 
        static bool validate(const char *publicKeyStr);
        static bool validate(PublicKey publicKey);
        static bool validate(const uint8_t *publicKeyBytes);
};

};
};
};

#endif

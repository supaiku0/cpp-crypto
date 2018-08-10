/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#ifndef PRIVATEKEY_H
#define PRIVATEKEY_H

#include "identities/encoding.h"

#include <cassert>
#include <cstring>

namespace Ark {
namespace Crypto {
namespace Identities {

/**************************************************
 * This is the private key class.
 *
 * @author Simon Downey <simon@ark.io>
 **************************************************/
class PrivateKey
{
	protected:
		uint8_t bytes_[PRIVATEKEY_SIZE];

    public:
    	PrivateKey() : bytes_() {};
        PrivateKey(const char *const newPrivateKeyStr);
        PrivateKey(const uint8_t *newPrivateKeyBytes);

        void setBytes(const uint8_t *newBytes);
        const uint8_t *getBytes();

        const char* c_str() const;

        static PrivateKey fromPassphrase(const char* const passphrase);
        static PrivateKey fromHex(const char *const privateKey);
        static PrivateKey fromWIFString(const char* wifStr, uint8_t wifByte);

        static bool validate(const char *privateKeyStr);
        static bool validate(PrivateKey privateKey);
        static bool validate(const uint8_t *privateKeyBytes);
};

};
};
};

#endif

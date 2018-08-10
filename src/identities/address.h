/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#ifndef ADDRESS_H
#define ADDRESS_H

#include "identities/encoding.h"
#include "identities/publickey.h"
#include "identities/privatekey.h"

#include <cstring>
#include <cassert>

namespace Ark {
namespace Crypto {
namespace Identities {

/**************************************************
 * This is the address class.
 *
 * @author Simon Downey <simon@ark.io>
 **************************************************/
class Address
{
	protected:
		uint8_t bytes_[ADDRESS_LENGTH];

	public:
        Address() : bytes_() {};
        Address(const char *const newAddressStr);

        const uint8_t *getBytes();
        void setBytes(const uint8_t *newBytes);

        /*************************************************/
        // const bool isValid() { return Address::validate(*this); };
        /*************************************************/
        const char* c_str() const;

        static Address fromPassphrase(const char* const passphrase, uint8_t networkVersion);
        static Address fromPublicKey(PublicKey publicKey, uint8_t networkVersion);
        static Address fromPrivateKey(PrivateKey privateKey, uint8_t networkVersion);

        static bool validate(Address address, uint8_t networkVersion);
};

};
};
};

#endif

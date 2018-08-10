/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#ifndef WIF_H
#define WIF_H

#include "identities/encoding.h"
#include "identities/privatekey.h"

#include <cstring>
#include <string>

namespace Ark {
namespace Crypto {
namespace Identities {

/**************************************************
 * This is the wif class.
 *
 * @author Simon Downey <simon@ark.io>
 **************************************************/
class WIF
{
	protected:
		uint8_t bytes_[WIF_SIZE];

    public:
      WIF() : bytes_() {};
      WIF(const char *const newWIFStr);
      WIF(const uint8_t *newWIFBytes);

      const uint8_t *getBytes();
      void setBytes(const uint8_t *newBytes);
      const char* c_str() const;

      static WIF fromPassphrase(const char *const passphrase, uint8_t wifByte);
};

};
};
};

#endif

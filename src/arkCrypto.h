/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#ifndef ARKCRYPTO_H
#define ARKCRYPTO_H

#define HAS_CRYPTO

#if (defined ARDUINO || defined ESP8266 || defined ESP32)
	#define USE_IOT
#endif

#include "enums/fees.h"
#include "enums/types.h"
#include "configuration/fee.h"


#include "identities/privatekey.h"
#include "identities/wif.h"
#include "identities/publickey.h"
#include "identities/address.h"

using namespace Ark::Crypto::Identities;
using namespace Ark::Crypto::Configuration;

#endif

/**
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef DESERIALIZER_H
#define DESERIALIZER_H

#include "helpers/helpers.h"
#include "helpers/encoding/hex.h"
#include "identities/publickey.h"
#include "identities/privatekey.h"
#include "transaction.h"

namespace Ark {
namespace Crypto {
namespace Transactions {

class Deserializer {

public:
    Deserializer(const std::string& serialized);
    Transaction deserialize();

private:
    void deserializeHeader(Transaction& transaction);
    void deserializeType(Transaction& transaction);
    void deserializeTransfer(Transaction& transaction);
    void deserializeSignatures(Transaction& transaction);

    std::string _serialized;
    std::vector<uint8_t> _binary;
    uint32_t _assetOffset;
};

}
}
}

#endif

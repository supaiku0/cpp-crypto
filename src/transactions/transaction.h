/**
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "helpers/helpers.h"
#include "helpers/encoding/hex.h"
#include "identities/publickey.h"
#include "identities/privatekey.h"
#include <string>

namespace Ark {
namespace Crypto {
namespace Transactions {

struct SecondSignature {
    std::string publicKey;
};

struct DelegateRegistration {
    std::string username;
};

struct MultiSignature {
    uint8_t min;
    uint8_t lifetime;
    std::vector<std::string> keysgroup;
};

union TransactionAsset {
    struct SecondSignature signature;
    struct DelegateRegistration delegate;
    std::vector<std::string> votes;
    struct MultiSignature multiSignature;

    ~TransactionAsset() {}
};


class Transaction
{
public:
    Transaction();
    std::string getId() const;
    std::string sign(std::string& passphrase) const;
    std::string secondSign(std::string& passphrase) const;
    bool verify() const;
    bool secondVerify(std::string& secondPublicKey) const;
    std::vector<uint8_t> toBytes(bool skipSignature = true, bool skipSecondSignature = true) const;

    uint8_t header = 0;
    uint8_t network = 0;
    uint8_t type = 0;
    uint8_t version = 0;
    TransactionAsset asset = {};
    uint32_t timelock_type = 0;
    std::vector<std::string> signatures = {};
    std::string id = "";
    std::string recipientId = "";
    std::string senderPublicKey = "";
    std::string secondSignature = "";
    std::string signature = "";
    std::string signSignature = "";
    std::string vendorField = "";
    std::string vendorFieldHex = "";
    uint32_t expiration = 0;
    uint32_t timestamp = 0;
    uint64_t amount = 0;
    uint64_t fee = 0;
    uint64_t timelock = 0;
};

}
}
}

#endif

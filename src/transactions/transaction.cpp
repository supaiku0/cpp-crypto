#include "transaction.h"
#include "bcl/Sha256.hpp"
#include "helpers/crypto.h"
#include "helpers/helpers.h"
#include "identities/privatekey.h"
#include "enums/types.h"

#include <iostream>

using namespace Ark::Crypto::Identities;

Ark::Crypto::Transactions::Transaction::Transaction()
{

}

std::string Ark::Crypto::Transactions::Transaction::getId() const
{
    auto bytes = this->toBytes();
    const auto shaHash = Sha256::getHash(&bytes[0], bytes.size());
    memcpy(&bytes[0], shaHash.value, shaHash.HASH_LEN);
    return BytesToHex(&bytes[0], &bytes[0] + shaHash.HASH_LEN);
}

std::string Ark::Crypto::Transactions::Transaction::sign(const char* passphrase)
{
    PrivateKey privateKey = PrivateKey::fromPassphrase(passphrase);
    this->senderPublicKey = Identities::PublicKey::fromPrivateKey(privateKey).toString();

    const auto bytes = this->toBytes();
    const auto hash = Sha256::getHash(&bytes[0], bytes.size());

    std::vector<uint8_t> buffer;
    cryptoSign(hash, privateKey, buffer);

    return BytesToHex(buffer.begin(), buffer.end());
}

std::string Ark::Crypto::Transactions::Transaction::secondSign(const char* passphrase)
{
    PrivateKey privateKey = PrivateKey::fromPassphrase(passphrase);
    const auto bytes = this->toBytes(false);
    const auto hash = Sha256::getHash(&bytes[0], bytes.size());

    std::vector<uint8_t> buffer;
    cryptoSign(hash, privateKey, buffer);

    return BytesToHex(buffer.begin(), buffer.end());
}

std::vector<uint8_t> Ark::Crypto::Transactions::Transaction::toBytes(bool skipSignature, bool skipSecondSignature) const
{
    std::vector<uint8_t> bytes;

    pack(bytes, this->type);
    pack(bytes, this->timestamp);

    const auto senderKeyBytes = HexToBytes(this->senderPublicKey.c_str());
    bytes.insert(std::end(bytes), std::begin(senderKeyBytes), std::end(senderKeyBytes));

    if (!this->recipientId.empty()) {
        // TODO:
    } else {
        std::vector<uint8_t> filler(21, 0);
        bytes.insert(std::end(bytes), std::begin(filler), std::end(filler));
    }

    if (!this->vendorField.empty()) {
        bytes.insert(std::end(bytes), std::begin(this->vendorField), std::end(this->vendorField));

        size_t diff = 64 - vendorField.length();
        if (diff > 0) {
            std::vector<uint8_t> filler(diff, 0);
            bytes.insert(std::end(bytes), std::begin(filler), std::end(filler));
        }

    } else {
        std::vector<uint8_t> filler(64, 0);
        bytes.insert(std::end(bytes), std::begin(filler), std::end(filler));
    }

    pack(bytes, this->amount);
    pack(bytes, this->fee);

    if (type == Enums::Types::SECOND_SIGNATURE_REGISTRATION) {
        const auto publicKeyBytes = HexToBytes(this->asset.signature.publicKey.c_str());
        bytes.insert(std::end(bytes), std::begin(publicKeyBytes), std::end(publicKeyBytes));

    } else if (type == Enums::Types::DELEGATE_REGISTRATION) {
        bytes.insert(std::end(bytes), std::begin(this->asset.delegate.username), std::end(this->asset.delegate.username));

    } else if (type == Enums::Types::VOTE) {
        const auto joined = join(this->asset.votes);
        bytes.insert(std::end(bytes), std::begin(joined), std::end(joined));

    } else if (type == Enums::Types::MULTI_SIGNATURE_REGISTRATION) {
        pack(bytes, this->asset.multiSignature.min);
        pack(bytes, this->asset.multiSignature.lifetime);
        const auto joined = join(this->asset.multiSignature.keysgroup);
        bytes.insert(std::end(bytes), std::begin(joined), std::end(joined));
    }

    if (!skipSignature && !this->signature.empty()) {
        const auto signatureBytes = HexToBytes(this->signature.c_str());
        bytes.insert(std::end(bytes), std::begin(signatureBytes), std::end(signatureBytes));
    }

    if (!skipSecondSignature && !this->secondSignature.empty()) {
        const auto secondSignatureBytes = HexToBytes(this->secondSignature.c_str());
        bytes.insert(std::end(bytes), std::begin(secondSignatureBytes), std::end(secondSignatureBytes));
    }

    return bytes;
}


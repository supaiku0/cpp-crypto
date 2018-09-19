#include "deserializer.h"
#include "bcl/Sha256.hpp"
#include "helpers/crypto.h"
#include "identities/address.h"
#include "enums/types.h"

#include <iostream>
#include <numeric>
#include <iterator>
#include <algorithm>
#include <sstream>

namespace Ark {
namespace Crypto {
namespace Transactions {

Deserializer::Deserializer(const std::string& serialized)
    : _serialized(serialized), _binary(HexToBytes(serialized.c_str())), _assetOffset(0)
{

}

Transaction Deserializer::deserialize()
{
    Transaction transaction;

    for (std::vector<uint8_t>::const_iterator i = this->_binary.begin(); i != this->_binary.end(); ++i)
        std::cout << (unsigned)*i << ' ';

    std::cout << std::endl;

    deserializeHeader(transaction);
    deserializeType(transaction);
    deserializeSignatures(transaction);

    if (transaction.version == 1) {
        handleVersionOne(transaction);
    }

    std::cout << "AssetOffset: " << (unsigned) _assetOffset << std::endl;
    return transaction;
}

void Deserializer::deserializeHeader(Transaction& transaction)
{
    unpack(&transaction.header, &this->_binary[0]); // 1 Byte
    unpack(&transaction.version, &this->_binary[1]); // 1 Byte
    unpack(&transaction.network, &this->_binary[2]); // 1 Byte
    unpack(&transaction.type, &this->_binary[3]); // 1 Byte
    unpack(&transaction.timestamp, &this->_binary[4]); // 4 Byte

    // 33 Byte
    transaction.senderPublicKey = BytesToHex(this->_binary.begin() + 8, this->_binary.begin() + 33 + 8);

    unpack(&transaction.fee, &this->_binary[41]); // 8 Byte

    uint8_t vendorFieldOffset = (41 + 8 + 1) * 2;
    uint8_t vendorFieldLength = 0;
    unpack(&vendorFieldLength, &this->_binary[49]); // 1 Byte
    if (vendorFieldLength > 0) {
        transaction.vendorFieldHex = this->_serialized.substr(vendorFieldOffset, vendorFieldLength * 2);
    }

    _assetOffset = vendorFieldOffset + vendorFieldLength * 2;
}

void Deserializer::deserializeType(Transaction& transaction)
{
    switch (transaction.type) {
    case  Enums::Types::TRANSFER: {
        deserializeTransfer(transaction);
        break;
    }
    case  Enums::Types::SECOND_SIGNATURE_REGISTRATION: {
        break;
    }
    case  Enums::Types::DELEGATE_REGISTRATION: {
        break;
    }
    case  Enums::Types::VOTE: {
        break;
    }
    case  Enums::Types::MULTI_SIGNATURE_REGISTRATION: {
        break;
    }
    case  Enums::Types::IPFS: {
        break;
    }
    case  Enums::Types::TIMELOCK_TRANSFER: {
        break;
    }
    case  Enums::Types::MULTI_PAYMENT: {
        break;
    }
    case  Enums::Types::DELEGATE_RESIGNATION: {
        break;
    }
    }
}

static std::string base58encodeAddress(uint8_t* source) {
    // Magic numbers from Base58Check::pubkeyHashToBase58Check
    uint8_t temp[21 + 4];
    char out[21 + 4];

    std::vector<uint8_t> buf;
    std::copy(source, source + 21, std::back_inserter(buf));
    Base58Check::bytesToBase58Check(&buf[0], temp, 21, out);

    return std::string(out);
}

void Deserializer::deserializeTransfer(Transaction& transaction)
{
    unpack(&transaction.amount, &this->_binary[_assetOffset / 2]);
    unpack(&transaction.expiration, &this->_binary[_assetOffset / 2 + 8]);
    transaction.recipientId = base58encodeAddress(&this->_binary[(_assetOffset / 2) + 12]);

    _assetOffset += (8 + 4 + 21) * 2;
}

void Deserializer::deserializeSignatures(Transaction& transaction)
{
    std::string signature = this->_serialized.substr(_assetOffset);

    size_t multiSignatureOffset = 0;
    if (!signature.empty()) {
        size_t signatureLength = 0;

        std::stringstream ss;
        ss << std::hex << signature.substr(2, 2);
        ss >> signatureLength;
        signatureLength += 2;

        transaction.signature = this->_serialized.substr(_assetOffset, signatureLength * 2);
        multiSignatureOffset += signatureLength * 2;
        transaction.secondSignature= this->_serialized.substr((_assetOffset + signatureLength * 2));

        if (!transaction.secondSignature.empty()) {
            if (transaction.secondSignature.substr(0, 2) == "ff") {
                transaction.secondSignature = "";
            } else {

                size_t secondSignatureLength = 0;

                std::stringstream ss;
                ss << std::hex << transaction.secondSignature.substr(2, 2);
                ss >> secondSignatureLength;
                secondSignatureLength += 2;

                transaction.secondSignature = transaction.secondSignature.substr(0, secondSignatureLength * 2);
                multiSignatureOffset += secondSignatureLength * 2;
            }
        }

        std::string signatures = this->_serialized.substr(_assetOffset + multiSignatureOffset);
        if (!signatures.empty() && signatures.substr(0, 2) == "ff") {
            signatures = signatures.substr(2);

            while (!signatures.empty()) {

                size_t multiSignatureLength = 0;
                std::stringstream ss;
                ss << std::hex << signatures.substr(2, 2);
                ss >> multiSignatureLength;
                multiSignatureLength += 2;

                if (multiSignatureLength > 0) {
                    transaction.signatures.push_back(signatures.substr(0, multiSignatureLength * 2));
                }

                signatures = signatures.substr(multiSignatureLength * 2);
            }
        }
    }

}

void Deserializer::handleVersionOne(Transaction& transaction)
{
    transaction.signSignature = transaction.secondSignature;

    if (transaction.type == Enums::Types::VOTE) {
        const auto publicKey = Identities::PublicKey::fromHex(transaction.senderPublicKey.c_str());
        const auto address = Identities::Address::fromPublicKey(publicKey, transaction.network);
        transaction.recipientId = address.toString();
    }

    if (transaction.type == Enums::Types::MULTI_SIGNATURE_REGISTRATION) {
        std::for_each(transaction.asset.multiSignature.keysgroup.begin(),
                       transaction.asset.multiSignature.keysgroup.end(),
           [](std::string& key) { key.insert(0, "+"); });
    }

    if (!transaction.vendorFieldHex.empty()) {
        const auto bytes = HexToBytes(transaction.vendorFieldHex.c_str());
        transaction.vendorField = std::string(bytes.begin(), bytes.end());
    }

    if (transaction.id.empty()) {
        transaction.id = transaction.getId();
    }

    if (transaction.type == Enums::Types::SECOND_SIGNATURE_REGISTRATION ||
            transaction.type == Enums::Types::MULTI_SIGNATURE_REGISTRATION) {
        const auto publicKey = Identities::PublicKey::fromHex(transaction.senderPublicKey.c_str());
        const auto address = Identities::Address::fromPublicKey(publicKey, transaction.network);
        transaction.recipientId = address.toString();
    }
}

}
}
}




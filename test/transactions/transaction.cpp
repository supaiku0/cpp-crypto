#include "gtest/gtest.h"
#include "arkCrypto.h"
#include <unordered_map>

namespace {
    const auto text = "Computer science is no more about computers than astronomy is about telescopes.";
    const auto passphrase = "viable weasel wage promote praise inflict jaguar tackle color unusual exclude direct";
    const auto expectedSignature = "3044022021704f2adb2e4a10a3ddc1d7d64552b8061c05f6d12a168c69091c75581d611402200edf37689d2786fc690af9f0f6fa1f629c95695039f648a6d455484302402e93";
    const auto expectedPublicKey = "0275776018638e5c40f1b922901e96cac2caa734585ef302b4a2801ee9a338a456";
    const auto expectedJsonString = "{\"publickey\":\"0275776018638e5c40f1b922901e96cac2caa734585ef302b4a2801ee9a338a456\",\"signature\":\"3044022021704f2adb2e4a10a3ddc1d7d64552b8061c05f6d12a168c69091c75581d611402200edf37689d2786fc690af9f0f6fa1f629c95695039f648a6d455484302402e93\",\"message\":\"Computer science is no more about computers than astronomy is about telescopes.\"}";
}

TEST(transactions, create)
{
    Ark::Crypto::Transactions::Transaction tr;

    Ark::Crypto::Transactions::DelegateRegistration dr = { .username = "AAAAA" };
    tr.asset.delegate = dr;
    tr.type = 2;
    tr.timestamp = 999999;
    tr.senderPublicKey = "0275776018638e5c40f1b922901e96cac2caa734585ef302b4a2801ee9a338a456";

    auto bla = tr.toBytes();

    for (std::vector<uint8_t>::const_iterator i = bla.begin(); i != bla.end(); ++i)
        std::cout << (unsigned)*i << ' ';

    std::cout << std::endl;

}

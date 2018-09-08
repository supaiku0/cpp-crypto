#include "gtest/gtest.h"
#include "arkCrypto.h"

// #include <iostream>
#include <unordered_map>

namespace {
    const auto text = "Computer science is no more about computers than astronomy is about telescopes.";
    const auto passphrase = "viable weasel wage promote praise inflict jaguar tackle color unusual exclude direct";
    const auto expectedSignature = "3044022021704f2adb2e4a10a3ddc1d7d64552b8061c05f6d12a168c69091c75581d611402200edf37689d2786fc690af9f0f6fa1f629c95695039f648a6d455484302402e93";
    const auto expectedPublicKey = "0275776018638e5c40f1b922901e96cac2caa734585ef302b4a2801ee9a338a456";
    const auto expectedJsonString = "{\"publickey\":\"0275776018638e5c40f1b922901e96cac2caa734585ef302b4a2801ee9a338a456\",\"signature\":\"3044022021704f2adb2e4a10a3ddc1d7d64552b8061c05f6d12a168c69091c75581d611402200edf37689d2786fc690af9f0f6fa1f629c95695039f648a6d455484302402e93\",\"message\":\"Computer science is no more about computers than astronomy is about telescopes.\"}";

}

TEST(utils, message_sign)
{
    Ark::Crypto::Utils::Message message;

    message.sign(text, passphrase);

    ASSERT_STREQ( expectedSignature, HexStr(message.signature).c_str() );
}

TEST(utils, message_to_array)
{
    Ark::Crypto::Utils::Message message;

    message.sign(text, passphrase);

    const auto messageArray = message.toArray();

    ASSERT_STREQ("publickey", messageArray[0].first);
    const PublicKey publicKey(messageArray[0].second);
    ASSERT_STREQ(expectedPublicKey, publicKey.c_str());

    ASSERT_STREQ("signature", messageArray[1].first);
    ASSERT_STREQ(expectedSignature, HexStr(messageArray[1].second, messageArray[1].second + (messageArray[1].second[1] + 2)).c_str());

    ASSERT_STREQ("message", messageArray[2].first);
    ASSERT_STREQ(text, reinterpret_cast<const char*>(messageArray[2].second));
}

TEST(utils, message_to_json)
{
    Ark::Crypto::Utils::Message message;

    message.sign(text, passphrase);

    ASSERT_STREQ(expectedJsonString, message.toJson().c_str() );
}

TEST(utils, message_to_string)
{
    Ark::Crypto::Utils::Message message;

    message.sign(text, passphrase);

    ASSERT_STREQ( expectedJsonString, message.toString().c_str() );
}

TEST(utils, message_verify)
{
    Ark::Crypto::Utils::Message message;

    message.sign(text, passphrase);

    ASSERT_EQ(1, message.verify());
}

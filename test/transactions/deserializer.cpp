#include "gtest/gtest.h"
#include "arkCrypto.h"

TEST(transactions, deserialize_transfer)
{
    Ark::Crypto::Transactions::Deserializer deserializer("ff011e0007627802034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed19280969800000000000b48656c6c6f20576f726c6400c2eb0b00000000000000001e0995750207ecaf0ccf251c1265b92ad84f553662304402205616d6e361439d67a5c2067bbfc8fce61b93061a4fa113315a1c5cf965ff6f3202200a1d99caaa98aeebcec04edd5365352500addb830c79f49b9de484ec616bb1e1");
    auto actual = deserializer.deserialize();

    ASSERT_EQ(actual.header, 0xFF);
    ASSERT_EQ(actual.version, 1);
    ASSERT_EQ(actual.network, 30);
    ASSERT_EQ(actual.type, Ark::Crypto::Enums::Types::TRANSFER);
    ASSERT_EQ(actual.timestamp, 41443847);
    ASSERT_EQ(actual.senderPublicKey, "034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192");
    ASSERT_EQ(actual.fee, 10000000);
    ASSERT_EQ(actual.vendorFieldHex, "48656c6c6f20576f726c64");
    ASSERT_EQ(actual.vendorField, "Hello World");
    ASSERT_EQ(actual.amount, 200000000);
    ASSERT_EQ(actual.expiration, 0);
    ASSERT_EQ(actual.recipientId, "D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib");
    ASSERT_EQ(actual.signature, "304402205616d6e361439d67a5c2067bbfc8fce61b93061a4fa113315a1c5cf965ff6f3202200a1d99caaa98aeebcec04edd5365352500addb830c79f49b9de484ec616bb1e1");
}

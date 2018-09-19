#include "gtest/gtest.h"
#include "arkCrypto.h"

TEST(transactions, deserialize_transfer)
{
    // transfer/passphrase-with-vendor-field.json
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


TEST(transactions, deserialize_second_signature_registration)
{
    // second_signature_registration/second-passphrase.json
    Ark::Crypto::Transactions::Deserializer deserializer("ff011e013bc27502034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed1920065cd1d000000000003699e966b2525f9088a6941d8d94f7869964a000efe65783d78ac82e1199fe609304402202aab49477dd3531e4473196d08fbd7c00ebb79223d5eaaeaf02c52c4041a86cf02201a7d82655f9b1d22af3ea94e6f183649bb4610cdeca3b9e20d6c8773f869831c");
    auto actual = deserializer.deserialize();

    ASSERT_EQ(actual.header, 0xFF);
    ASSERT_EQ(actual.version, 1);
    ASSERT_EQ(actual.network, 30);
    ASSERT_EQ(actual.type, Ark::Crypto::Enums::Types::SECOND_SIGNATURE_REGISTRATION);
    ASSERT_EQ(actual.timestamp, 41271867);
    ASSERT_EQ(actual.senderPublicKey, "034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192");
    ASSERT_EQ(actual.fee, 500000000);
    ASSERT_EQ(actual.amount, 0);
    ASSERT_EQ(actual.expiration, 0);
    ASSERT_EQ(actual.asset.signature.publicKey, "03699e966b2525f9088a6941d8d94f7869964a000efe65783d78ac82e1199fe609");
    ASSERT_EQ(actual.signature, "304402202aab49477dd3531e4473196d08fbd7c00ebb79223d5eaaeaf02c52c4041a86cf02201a7d82655f9b1d22af3ea94e6f183649bb4610cdeca3b9e20d6c8773f869831c");

    // special case as the type 1 transaction itself has no recipientId
    const auto publicKey = Ark::Crypto::Identities::PublicKey::fromHex(actual.senderPublicKey.c_str());
    const auto address = Ark::Crypto::Identities::Address::fromPublicKey(publicKey, actual.network);
    ASSERT_EQ(actual.recipientId, address.toString());
}

TEST(transactions, deserialize_delegate_registration)
{
    // delegate_registration/second-passphrase.json
    Ark::Crypto::Transactions::Deserializer deserializer("ff011e02b0b87502034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed19200f90295000000000009626f6c646e696e6a613045022100f21b742fa052cd18de43328e1d068539ba7cbe9d33a9dcbd862a82871383955d0220053b06d22ed3e3ad6168c6b27aa0ec68e7e40958c7709aec0e1555087ea9ad94304402207da580da4feec955edcb8e8eb36947867b439de3d28d38e58c844fd8c45b564302200e6741b6ad11c2588a57b3afd180df1e9b345d48a9c2ae98be57dced869cf38c");
    auto actual = deserializer.deserialize();

    ASSERT_EQ(actual.header, 0xFF);
    ASSERT_EQ(actual.version, 1);
    ASSERT_EQ(actual.network, 30);
    ASSERT_EQ(actual.type, Ark::Crypto::Enums::Types::DELEGATE_REGISTRATION);
    ASSERT_EQ(actual.timestamp, 41269424);
    ASSERT_EQ(actual.senderPublicKey, "034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192");
    ASSERT_EQ(actual.fee, 2500000000);
    ASSERT_EQ(actual.amount, 0);
    ASSERT_EQ(actual.expiration, 0);
    ASSERT_EQ(actual.asset.delegate.username, "boldninja");

    ASSERT_EQ(actual.signature, "3045022100f21b742fa052cd18de43328e1d068539ba7cbe9d33a9dcbd862a82871383955d0220053b06d22ed3e3ad6168c6b27aa0ec68e7e40958c7709aec0e1555087ea9ad94");
    ASSERT_EQ(actual.secondSignature, "304402207da580da4feec955edcb8e8eb36947867b439de3d28d38e58c844fd8c45b564302200e6741b6ad11c2588a57b3afd180df1e9b345d48a9c2ae98be57dced869cf38c");
    ASSERT_EQ(actual.secondSignature, actual.signSignature);
}

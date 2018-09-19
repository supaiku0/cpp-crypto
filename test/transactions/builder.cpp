#include "gtest/gtest.h"
#include "arkCrypto.h"

TEST(transactions, build_transfer)
{
    const auto actual = Ark::Crypto::Transactions::Builder::buildTransfer("D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib", 100000000, "", "Secret passphrase");
    ASSERT_EQ(actual.type, Ark::Crypto::Enums::Types::TRANSFER);
    ASSERT_EQ(actual.fee, Ark::Crypto::Configuration::Fee().get(Ark::Crypto::Enums::Types::TRANSFER));
    ASSERT_EQ(actual.recipientId, "D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib");
    ASSERT_EQ(actual.amount, 100000000);
    ASSERT_EQ(actual.vendorField, "");
    //ASSERT_EQ(actual.id, "5f7340807b6b3eff981a5f244e7fe266ef3257e536bb5dcab721630c65aec84b");
    //ASSERT_EQ(actual.signature, "304402205616d6e361439d67a5c2067bbfc8fce61b93061a4fa113315a1c5cf965ff6f3202200a1d99caaa98aeebcec04edd5365352500addb830c79f49b9de484ec616bb1e1");
}


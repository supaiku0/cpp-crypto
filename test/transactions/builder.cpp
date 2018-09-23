#include "gtest/gtest.h"
#include "arkCrypto.h"

TEST(transactions, build_transfer)
{
    const auto actual = Ark::Crypto::Transactions::Builder::buildTransfer("D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib", 100000000, "", "Secret passphrase");
    ASSERT_EQ(Ark::Crypto::Enums::Types::TRANSFER, actual.type);
    ASSERT_EQ(Ark::Crypto::Configuration::Fee().get(Ark::Crypto::Enums::Types::TRANSFER), actual.fee);
    ASSERT_EQ("D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib", actual.recipientId);
    ASSERT_EQ(100000000, actual.amount);
    ASSERT_EQ("", actual.vendorField);
}


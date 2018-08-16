#include "gtest/gtest.h"

#include "arkCrypto.h"

TEST(enums, fees)
{
    Ark::Crypto::Enums::Fees fees;
    
    auto feeZERO = fees.TRANSFER;
    ASSERT_EQ(10000000, feeZERO);

    auto feeONE = fees.SECOND_SIGNATURE_REGISTRATION;
    ASSERT_EQ(500000000, feeONE);

    auto feeTWO = fees.DELEGATE_REGISTRATION;
    ASSERT_EQ(2500000000, feeTWO);

    auto feeTHREE = fees.VOTE;
    ASSERT_EQ(100000000, feeTHREE);

    auto feeFOUR = fees.MULTI_SIGNATURE_REGISTRATION;
    ASSERT_EQ(500000000, feeFOUR);

    auto feeFIVE = fees.IPFS;
    ASSERT_EQ(0, feeFIVE);

    auto feeSIX = fees.TIMELOCK_TRANSFER;
    ASSERT_EQ(0, feeSIX);

    auto feeSEVEN = fees.MULTI_PAYMENT;
    ASSERT_EQ(0, feeSEVEN);

    auto feeEIGHT = fees.DELEGATE_RESIGNATION;
    ASSERT_EQ(0, feeEIGHT);
}

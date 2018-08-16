#include "gtest/gtest.h"

#include "arkCrypto.h"

TEST(configuration, fee_get)
{
    Ark::Crypto::Configuration::Fee fee;
    ASSERT_EQ(10000000, fee.get(0));
    ASSERT_EQ(500000000, fee.get(1));
    ASSERT_EQ(2500000000, fee.get(2));
    ASSERT_EQ(100000000, fee.get(3));
    ASSERT_EQ(500000000, fee.get(4));
    ASSERT_EQ(0, fee.get(5));
    ASSERT_EQ(0, fee.get(6));
    ASSERT_EQ(0, fee.get(7));
    ASSERT_EQ(0, fee.get(8));
}

TEST(configuration, fee_set)
{
    Ark::Crypto::Configuration::Fee fee;
    fee.set(0, 20000000);
    fee.set(1, 1000000000);
    fee.set(2, 4000000000);
    fee.set(3, 200000000);
    fee.set(4, 1000000000);
    fee.set(5, 1);
    fee.set(6, 1);
    fee.set(7, 1);
    fee.set(8, 1);

    ASSERT_EQ(20000000, fee.get(0));
    ASSERT_EQ(1000000000, fee.get(1));
    ASSERT_EQ(4000000000, fee.get(2));
    ASSERT_EQ(200000000, fee.get(3));
    ASSERT_EQ(1000000000, fee.get(4));
    ASSERT_EQ(1, fee.get(5));
    ASSERT_EQ(1, fee.get(6));
    ASSERT_EQ(1, fee.get(7));
    ASSERT_EQ(1, fee.get(8));
}

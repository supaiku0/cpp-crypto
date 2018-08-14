#include "gtest/gtest.h"

#include "arkCrypto.h"

TEST(configuration, fee_get)
{
    Fee fee;
    ASSERT_EQ(10000000u, fee.get(1));
    ASSERT_EQ(500000000u, fee.get(2));
    ASSERT_EQ(2500000000u, fee.get(3));
    ASSERT_EQ(100000000u, fee.get(4));
    ASSERT_EQ(500000000u, fee.get(5));
    ASSERT_EQ(0, fee.get(6));
    ASSERT_EQ(0, fee.get(7));
    ASSERT_EQ(0, fee.get(8));
    ASSERT_EQ(0, fee.get(9));
}

TEST(configuration, fee_set)
{
    Fee fee;
    fee.set(1, 20000000);
    fee.set(2, 1000000000);
    fee.set(3, 4000000000);
    fee.set(4, 200000000);
    fee.set(5, 1000000000);
    fee.set(6, 1);
    fee.set(7, 1);
    fee.set(8, 1);
    fee.set(9, 1);
    
    ASSERT_EQ(20000000, fee.get(1));
    ASSERT_EQ(1000000000, fee.get(2));
    ASSERT_EQ(4000000000, fee.get(3));
    ASSERT_EQ(200000000, fee.get(4));
    ASSERT_EQ(1000000000, fee.get(5));
    ASSERT_EQ(1, fee.get(6));
    ASSERT_EQ(1, fee.get(7));
    ASSERT_EQ(1, fee.get(8));
    ASSERT_EQ(1, fee.get(9));
}

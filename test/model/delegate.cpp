

#include "gtest/gtest.h"
#include "models/one/delegate/delegate.h"

TEST(model, construct_delegate)
{
	ARK::Delegate delegate(
		"sleepdeficit",
		"DHQ4Fjsyiop3qBR4otAjAu6cBHkgRELqGA",
		"0275776018638e5c40f1b922901e96cac2caa734585ef302b4a2801ee9a338a456",
		"8418345341862",
		35810,
		3164,
		31,
		0.06,
		91.88
	);
	ASSERT_STREQ("sleepdeficit", delegate.username());
	ASSERT_STREQ("DHQ4Fjsyiop3qBR4otAjAu6cBHkgRELqGA", delegate.address().c_str());
	ASSERT_STREQ("0275776018638e5c40f1b922901e96cac2caa734585ef302b4a2801ee9a338a456", delegate.public_key().c_str());
	ASSERT_STREQ("8418345341862", delegate.vote().arktoshi());
	ASSERT_EQ(35810, delegate.produced_blocks());
	ASSERT_EQ(3164, delegate.missed_blocks());
	ASSERT_EQ(31, delegate.rate());
	ASSERT_EQ(0.06, delegate.approval());
	ASSERT_EQ(91.88, delegate.productivity());
}

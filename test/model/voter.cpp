

#include "gtest/gtest.h"
#include "models/one/voter/voter.h"

TEST(model, construct_voter)
{
	ARK::Voter voter(
		"sleepdeficit",
		"DHQ4Fjsyiop3qBR4otAjAu6cBHkgRELqGA",
		"0275776018638e5c40f1b922901e96cac2caa734585ef302b4a2801ee9a338a456",
		"8419145341862"
	);
	ASSERT_STREQ("sleepdeficit", voter.username());
	ASSERT_STREQ("DHQ4Fjsyiop3qBR4otAjAu6cBHkgRELqGA", voter.address().c_str());
	ASSERT_STREQ("0275776018638e5c40f1b922901e96cac2caa734585ef302b4a2801ee9a338a456", voter.public_key().c_str());
	ASSERT_STREQ("8419145341862", voter.balance().arktoshi());
}

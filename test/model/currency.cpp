﻿

#include "gtest/gtest.h"
#include "models/one/currency/currency.h"

namespace
{
	const auto ark_symbol = "Ѧ";
}

TEST(model, construct_currency)
{
	ARK::Model::Currency currency(
		"ARK",
		"ark",
		ark_symbol
	);
	ASSERT_STREQ("ARK", currency.ticker());
	ASSERT_STREQ("ark", currency.name());
	ASSERT_STREQ(ark_symbol, currency.symbol());
}

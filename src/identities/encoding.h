/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#ifndef ENCODING_H
#define ENCODING_H

#include "bcl/Base58Check.hpp"
#include "bcl/CurvePoint.hpp"
#include "bcl/Ecdsa.hpp"
#include "bcl/FieldInt.hpp"
#include "bcl/Ripemd160.hpp"
#include "bcl/Sha256Hash.hpp"
#include "bcl/Sha256.hpp"
#include "bcl/Sha512.hpp"
#include "bcl/Uint256.hpp"
 
namespace Ark {
namespace Crypto {
namespace Identities {

	const auto ADDRESS_LENGTH = 34u;
	const auto COMPRESSED_PUBLICKEY_SIZE = 33u;
	const auto PRIVATEKEY_SIZE = 32u;
	const auto WIF_SIZE = 52u;

};
};
};

#include <vector>
#include <memory>

/**************************************************
 * Hex Helpers
 **************************************************/
template<typename T>
static std::string BytesToHex(const T itbegin, const T itend, bool fSpaces = false)
{
	std::string rv;
	static const char hexmap[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f'
	};
	rv.reserve((itend - itbegin) * 3);
	for (T it = itbegin; it < itend; ++it)
	{
		unsigned char val = (unsigned char)(*it);
		if (fSpaces && it != itbegin)
			rv.push_back(' ');
		rv.push_back(hexmap[val >> 4]);
		rv.push_back(hexmap[val & 15]);
	}

	return rv;
};

/*************************************************/

template<typename T>
static inline std::string BytesToHex(const T& vch, bool fSpaces = false)
{
	return BytesToHex(vch.begin(), vch.end(), fSpaces);
};

/*************************************************/

static const signed char p_util_hexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
-1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

/*************************************************/

static signed char HexDigit(char c)
{
	return p_util_hexdigit[(unsigned char)c];
};

/*************************************************/

static std::vector<unsigned char> ParseHex(const char* psz)
{
	// convert hex dump to vector
	std::vector<unsigned char> vch;
	while (true)
	{
		while (isspace(*psz))
			psz++;
		signed char c = HexDigit(*psz++);
		if (c == (signed char)-1)
			break;
		unsigned char n = (c << 4);
		c = HexDigit(*psz++);
		if (c == (signed char)-1)
			break;
		n |= c;
		vch.push_back(n);
	}
	return vch;
};

/*************************************************/

template<typename T>
std::string HexStr(const T itbegin, const T itend, bool fSpaces = false)
{
	std::string rv;
	const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	rv.reserve((itend - itbegin) * 3);
	for (T it = itbegin; it < itend; ++it)
	{
		unsigned char val = (unsigned char)(*it);
		if (fSpaces && it != itbegin)
			rv.push_back(' ');
		rv.push_back(hexmap[val >> 4]);
		rv.push_back(hexmap[val & 15]);
	}

	return rv;
}

/*************************************************/

template<typename T>
inline std::string HexStr(const T& vch, bool fSpaces = false)
{
	return HexStr(vch.begin(), vch.end(), fSpaces);
}
/*************************************************/
/*************************************************/


/**************************************************
 * More Helpers
 **************************************************/
// #include <random>

// static uint8_t getRandomDigit()
// {	
// 	std::default_random_engine generator;
// 	std::uniform_int_distribution<uint32_t> distribution(0, 255);
// 	return distribution(generator);
// };

// static void Sanitize(
// 		uint8_t* buffer,
// 		size_t size
// ) {
// 	for (unsigned int i = 0; i < size; i++)
// 	{
// 		buffer[i] = getRandomDigit();
// 	};
// };
/*************************************************/

#endif

/**
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef ENCODING_H
#define ENCODING_H

#include "helpers/helpers.h"
#include "bcl/Ecdsa.hpp"
#include <cassert>
#include <memory>
#include <vector>

/**/

const auto ADDRESS_LENGTH = 34u;
const auto COMPRESSED_PUBLICKEY_SIZE = 33u;
const auto PRIVATEKEY_SIZE = 32u;
const auto WIF_SIZE = 52u;

/**/
/**/

/**
 * Hex Helpers
 **/
template<typename T>
static inline std::string BytesToHex(const T itbegin, const T itend, bool fSpaces = false)
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

/**/

template<typename T>
static inline std::string BytesToHex(const T& vch, bool fSpaces = false)
{
    return BytesToHex(vch.begin(), vch.end(), fSpaces);
};

/**/

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

/**/

static inline signed char HexDigit(char c)
{
    return p_util_hexdigit[(unsigned char)c];
};

/**/

static inline std::vector<unsigned char> ParseHex(const char* psz)
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

/**/

template<typename T>
static inline std::string HexStr(const T itbegin, const T itend, bool fSpaces = false)
{
    std::string rv;
    const char hexmap[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
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
}

/**/

template<typename T>
static inline std::string HexStr(const T& vch, bool fSpaces = false)
{
    return HexStr(vch.begin(), vch.end(), fSpaces);
}

/**/
/**/

/**
 * DER Encode/Decode Helpers
 **/
static inline std::vector<uint8_t>& convert_to_der_buffer(std::vector<uint8_t>& buffer) {
    // if the sign bit is set, pad with a 0x00 byte
    if (buffer.size() > 1 && (buffer[0] & 0x80) != 0) {
        buffer.insert(buffer.begin(), 0x00);
    }
    return buffer;
};

/**/

static inline void decodeDER(std::vector<uint8_t>& signature, std::vector<uint8_t>& r, std::vector<uint8_t>& s)
{
    // Adapted from https://github.com/bitcoinjs/bip66/blob/master/index.js
    assert(signature.size() > 8); // DER sequence length is too short
    assert(signature.size() <  72); // DER sequence length is too long
    assert(signature[0] == 0x30); // Expected DER sequence
    assert(signature[1] == signature.size() - 2); // DER sequence length is invalid
    assert(signature[2] == 0x02); // Expected DER integer

    int lenR = signature[3];
    assert(lenR != 0); // R length is zero
    assert(5u + lenR <= signature.size()); // R length is too long
    assert(signature[4 + lenR] == 0x02); // Expected DER integer (2)

    int lenS = signature[5 + lenR];
    assert(lenS != 0); // S length is zero
    assert((6u + lenR + lenS) == signature.size()); // S length is invalid

    assert(signature[4] != 0x80); // R value is negative
    assert((lenR > 1));// && (signature[4] == 0x00) && !(signature[5] == 0x80)); // R value excessively padded

    assert(signature[lenR + 6] != 0x80); // S value is negative
    assert(lenS > 1);// && (signature[lenR + 6] != 0x00) && !(signature[lenR + 7] == 0x80)); // S value excessively padded

    // non-BIP66 - extract R, S values
    r = std::vector<uint8_t>(&signature[4], &signature[4] + lenR);
    s = std::vector<uint8_t>(&signature[6 + lenR], &signature[6 + lenR] + lenS);
}

/**/

static inline void toDER(const std::vector<uint8_t>& r, const std::vector<uint8_t>& s, std::vector<uint8_t>& signature) {
    // Adapted from https://github.com/bitcoinjs/bip66/blob/master/index.js
    auto lenR = r.size();
    auto lenS = s.size();
    assert(lenR != 0); // must be non zero
    assert(lenS != 0);
    assert(lenR <= 33); // must be less than 34 bytes
    assert(lenS <= 33);
    assert((r[0] & 0x80) == 0); // must not be negative
    assert((s[0] & 0x80) == 0);
    assert(lenR == 1 || r[0] != 0x00 || (r[1] & 0x80) != 0); //must have zero pad for negative number
    assert(lenS == 1 || s[0] != 0x00 || (s[1] & 0x80) != 0);

    auto it = r.begin();
    while (lenR > 1 && *it == 0 && *(it + 1) < 0x80) { --lenR; ++it; }
    it = s.begin();
    while (lenS > 1 && *it == 0 && *(it + 1) < 0x80) { --lenS; ++it; }

    signature.clear();
    signature.reserve(6 + lenR + lenS);

    // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
    signature.push_back(0x30); // [0]
    signature.push_back(static_cast<uint8_t>(6 + lenR + lenS - 2)); // [1]
    signature.push_back(0x02); // [2]
    signature.push_back(static_cast<uint8_t>(lenR)); // [3]
    signature.insert(signature.end(), r.begin(), r.end());  //[4]
    signature.push_back(0x02); // [4 + lenR]
    signature.push_back(static_cast<uint8_t>(lenS)); // [5 + lenR]
    signature.insert(signature.end(), s.begin(), s.end());  //[6 + lenR]
};

/**/

static inline void toDER(uint8_t packed_signature[PRIVATEKEY_SIZE * 2], std::vector<uint8_t>& signature) {
    std::vector<uint8_t> r(PRIVATEKEY_SIZE);
    std::vector<uint8_t> s(PRIVATEKEY_SIZE);

    memcpy(&r[0], packed_signature, PRIVATEKEY_SIZE);
    memcpy(&s[0], packed_signature + PRIVATEKEY_SIZE, PRIVATEKEY_SIZE);
    toDER(convert_to_der_buffer(r), convert_to_der_buffer(s), signature);
};

/**/

/**/

#endif

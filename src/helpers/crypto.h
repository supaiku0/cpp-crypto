/**
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef CRYPTO_H
#define CRYPTO_H

#include "helpers/helpers.h"
#include "helpers/encoding.h"
#include "identities/privatekey.h"
#include "bcl/Sha256.hpp"
#include "bcl/Sha256Hash.hpp"
#include "bcl/Uint256.hpp"
#include "rfc6979/rfc6979.h"
#include <vector>

static inline void cryptoSign(Sha256Hash hash, Ark::Crypto::Identities::PrivateKey privateKey, std::vector<uint8_t>& signature)
{
    Uint256 r;
    Uint256 s;

    uint8_t nonce32[32] = {};
    nonce_function_rfc6979(nonce32, hash.value, privateKey.toBytes(), nullptr, nullptr, 0);

    auto ret = Ecdsa::sign(Uint256(privateKey.toBytes()), hash, Uint256(nonce32), r, s);
    assert(ret);

    std::vector<uint8_t> r_der(PRIVATEKEY_SIZE);
    r.getBigEndianBytes(&r_der[0]);

    std::vector<uint8_t> s_der(PRIVATEKEY_SIZE);
    s.getBigEndianBytes(&s_der[0]);

    toDER(convert_to_der_buffer(r_der), convert_to_der_buffer(s_der), signature);
};

#endif

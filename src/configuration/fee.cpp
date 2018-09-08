/**
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#include "configuration/fee.h"

/**
 * @brief Get the transaction fee for the given type.
 *
 * @param const int type
 * @return int
 **/
unsigned int Ark::Crypto::Configuration::Fee::get(int type)
{
    return this->fees_[type];
};
/**/

/**
 * @brief Set the transaction fee for the given type.
 *
 * @param const int type
 * @param const int fee
 **/
void Ark::Crypto::Configuration::Fee::set(
        const int type,
        const unsigned int fee
) {
    this->fees_[type] = (unsigned int)fee;
};
/**/

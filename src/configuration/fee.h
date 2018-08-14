/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#ifndef FEE_H
#define FEE_H

#include "enums/types.h"
#include "enums/fees.h"

#include <unordered_map>

using namespace Ark::Crypto::Enums;

namespace Ark {
namespace Crypto {
namespace Configuration {
/**************************************************
 * This is the fee configuration class.
 *
 * @author Brian Faust <brian@ark.io>
 **************************************************/
class Fee
{
    private:
        /**************************************************
         * @brief The default transaction fees.
         *
         * @var const std::unordered_map<int, unsigned int> fees_
         **************************************************/
        std::unordered_map<int, unsigned int> fees_ = {
            { Types::TRANSFER,                      Fees::TRANSFER },
            { Types::SECOND_SIGNATURE_REGISTRATION, Fees::SECOND_SIGNATURE_REGISTRATION },
            { Types::DELEGATE_REGISTRATION,         Fees::DELEGATE_REGISTRATION }, // note: implementation limits integer capacity ~ 4000000000
            { Types::VOTE,                          Fees::VOTE },
            { Types::MULTI_SIGNATURE_REGISTRATION,  Fees::MULTI_SIGNATURE_REGISTRATION },
            { Types::IPFS,                          Fees::IPFS },
            { Types::TIMELOCK_TRANSFER,             Fees::TIMELOCK_TRANSFER },
            { Types::MULTI_PAYMENT,                 Fees::MULTI_PAYMENT },
            { Types::DELEGATE_RESIGNATION,          Fees::DELEGATE_RESIGNATION }
        };
        /*************************************************/

    public:
        unsigned int get(int type);
        void set(const int type, const unsigned int fee);
};
/*************************************************/

};
};
};

#endif

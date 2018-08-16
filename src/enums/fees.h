/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#ifndef FEES_H
#define FEES_H

namespace Ark {
namespace Crypto {
namespace Enums {
/**************************************************
 * This is the transaction fees class.
 *
 * @author Simon Downey <simon@ark.io>
 **************************************************/
struct Fees
{
    public:
    
    static const unsigned int TRANSFER                      = 10000000;
    static const unsigned int SECOND_SIGNATURE_REGISTRATION = 500000000;
    static const unsigned int DELEGATE_REGISTRATION         = 2500000000; // note: implementation limits integer capacity to ~ 4000000000
    static const unsigned int VOTE                          = 100000000;
    static const unsigned int MULTI_SIGNATURE_REGISTRATION  = 500000000;
    static const unsigned int IPFS                          = 0;
    static const unsigned int TIMELOCK_TRANSFER             = 0;
    static const unsigned int MULTI_PAYMENT                 = 0;
    static const unsigned int DELEGATE_RESIGNATION          = 0;
};
/**************************************************/
};
};
};

#endif

/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/

#ifndef NETWORK_H
#define NETWORK_H

#include "networks/abstractnetwork.h"
#include "networks/devnet.h"
#include "networks/mainnet.h"
#include "networks/testnet.h"

#include <vector>

namespace Ark {
namespace Crypto {
namespace Configuration {

using namespace Ark::Crypto::Networks;

/**************************************************
 * @brief This is the network configuration class.
 *
 * @author Simon Downey <simon@ark.io>
 **************************************************/
class Network
{
    private:
        AbstractNetwork network_;

    public:
        AbstractNetwork get();
        void set(AbstractNetwork network);
};
/*************************************************/
};
};
};

#endif




// /**************************************************
//  * This file is part of Ark Cpp Crypto.
//  *
//  * (c) Ark Ecosystem <info@ark.io>
//  *
//  * For the full copyright and license information, please view the LICENSE
//  * file that was distributed with this source code.
//  **************************************************/

// #ifndef NETWORK_H
// #define NETWORK_H

// #include "networks/abstractnetwork.h"
// #include "networks/devnet.h"
// #include "networks/mainnet.h"
// #include "networks/testnet.h"

// #include <vector>

// namespace Ark {
// namespace Crypto {
// namespace Configuration {

// using namespace Ark::Crypto::Networks;

// /**************************************************
//  * @brief This is the network configuration class.
//  *
//  * @author Simon Downey <simon@ark.io>
//  **************************************************/
// class Network
// {
//     private:
//         /**************************************************
//          * @brief: The network used for crypto operations.
//          *
//          * @var: \ArkEcosystem\Crypto\Networks\AbstractNetwork
//          **************************************************/
//         AbstractNetwork network_;
//         /*************************************************/

//     public:
//         /**************************************************
//          * @brief Get the network used for crypto operations.
//          *
//          * @return AbstractNetwork
//          **************************************************/
//         AbstractNetwork get()
//         {
//             return (this->network_.getBase58Prefix(BASE58_ADDRESS_P2PKH) == 0x00)
//                 ? (Devnet)
//                 : (this->network_);
//         }
//         /*************************************************/

//         /**************************************************
//          * @brief Set the network used for crypto operations.
//          *
//          * @param AbstractNetwork network
//          **************************************************/
//         void set(AbstractNetwork network)
//         {
//             this->network_ = network;
//         };
//         /*************************************************/
// };

// };
// };
// };

// #endif

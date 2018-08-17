/**************************************************
 * This file is part of Ark Cpp Crypto.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **************************************************/


#ifndef ABSTRACT_NETWORK_H
#define ABSTRACT_NETWORK_H

#include <cstring>
#include <vector>
#include <unordered_map>

namespace Ark {
namespace Crypto {
namespace Networks {


/**************************************************
 * @brief Base58 Prefix Type
 **************************************************/
enum Base58PrefixType : int { BASE58_ADDRESS_P2PKH = 0, BASE58_ADDRESS_P2SH, BASE58_WIF };
/**************************************************/
/**************************************************
 * @brief Base58 Prefix Container
 **************************************************/
struct base58_t
{
    uint8_t ADDRESS_P2PKH;
    uint8_t ADDRESS_P2SH;
    uint8_t WIF;
};
/**************************************************/


/**************************************************
 * @brief BIP32 Prefix Type
 **************************************************/
enum BIP32PrefixType : int { BIP32_PREFIX_XPUB = 0, BIP32_PREFIX_XPRV };
/**************************************************/
/**************************************************
 * @brief BIP32 Prefix Container
 **************************************************/
struct bip32_t
{
	long PREFIX_XPUB;
	long PREFIX_XPRV; 
};
/**************************************************/


/**************************************************
 * @brief This is the abstract network class.
 *
 * @author Simon Downey <simon@ark.io>
 **************************************************/
class AbstractNetwork
{
    protected:
        base58_t base58_;
        bip32_t bip32_;
        char epoch_[34];
        bool isLocked_;

    public:

        AbstractNetwork() = default;

        /**************************************************
         * @brief Abstract Network Parameter Instantiation interface
         * 
         * @param base58_t base58
         * @param bip32_t bip32
         * @param char epoch[34]
         * @param bool isEditable // default false
         **************************************************/
        AbstractNetwork(
            base58_t base58,
            bip32_t bip32,
            const char* epoch,
            bool locked = true
        ) : base58_(base58), bip32_(bip32), isLocked_(locked) {
            std::strncpy(this->epoch_, epoch, 34);
        };
        /**************************************************/

        virtual ~AbstractNetwork() { }

        const uint8_t getBase58Prefix(Base58PrefixType prefix) const;
        void setBase58Prefix(Base58PrefixType prefix, uint8_t newByte);

        const long getBIP32Prefix(BIP32PrefixType prefix) const;
        void setBIP32Prefix(BIP32PrefixType prefix, long newByte);

        const bool isLocked() const;

        const char* epoch() const;
        const int version() const;
};
/**************************************************/

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


// #ifndef ABSTRACT_NETWORK_H
// #define ABSTRACT_NETWORK_H

// #include <string>
// #include <vector>
// #include <unordered_map>

// namespace Ark {
// namespace Crypto {
// namespace Networks {


// /**************************************************
//  * @brief Base58 Prefix Type
//  **************************************************/
// enum Base58PrefixType : int { BASE58_ADDRESS_P2PKH = 0, BASE58_ADDRESS_P2SH, BASE58_WIF };
// /**************************************************/
// /**************************************************
//  * @brief Base58 Prefix Container
//  **************************************************/
// struct base58_t
// {
//     uint8_t ADDRESS_P2PKH;
//     uint8_t ADDRESS_P2SH;
//     uint8_t WIF;
// };
// /**************************************************/


// /**************************************************
//  * @brief BIP32 Prefix Type
//  **************************************************/
// enum BIP32PrefixType : int { BIP32_PREFIX_XPUB = 0, BIP32_PREFIX_XPRV };
// /**************************************************/
// /**************************************************
//  * @brief BIP32 Prefix Container
//  **************************************************/
// struct bip32_t
// {
// 	long PREFIX_XPUB;
// 	long PREFIX_XPRV; 
// };
// /**************************************************/


// /**************************************************
//  * @brief This is the abstract network class.
//  *
//  * @author Simon Downey <simon@ark.io>
//  **************************************************/
// class AbstractNetwork
// {
//     protected:
//         /**************************************************
//          * @brief Base58 Prefixes
//          **************************************************/
//         base58_t base58_;
//         /**************************************************/
//         /**************************************************
//          * @brief BIP32 Prefixes
//          **************************************************/
//         bip32_t bip32_;
//         /**************************************************/
//         /**************************************************
//          * @brief Network Epoch
//          **************************************************/
//         char epoch_[34];
//         /**************************************************/

//         /**************************************************
//          * @brief Determines if parameters are locked
//          **************************************************/
//         bool isLocked_;
//         /**************************************************/

//     public:
//         /**************************************************
//          * @brief Abstract Network Default interface
//          **************************************************/
//         AbstractNetwork() = default;
//         /**************************************************/
        
//         /**************************************************
//          * @brief Abstract Network Parameter Instantiation interface
//          * 
//          * @param base58_t base58
//          * @param bip32_t bip32
//          * @param char epoch[34]
//          * @param bool isEditable // default false
//          **************************************************/
//         AbstractNetwork(
//             base58_t base58,
//             bip32_t bip32,
//             const char* epoch,
//             bool locked = true
//         ) : base58_(base58), bip32_(bip32), isLocked_(locked)  {
//           std::strncpy(this->epoch_, epoch, 34);
//         };
//         /**************************************************/

//         /**************************************************
//          * @brief Deconstructor
//          **************************************************/
//         virtual ~AbstractNetwork() { }
//         /**************************************************/


//         /**************************************************
//          * @brief get the networks Base58 prefix byte given a prefix name
//          * 
//          * @param Base58PrefixType prefix
//          * @return uint8_t
//          **************************************************/
//         const uint8_t getBase58Prefix(Base58PrefixType prefix) const
//         {
//             switch (prefix) {
//                 case 0: return this->base58_.ADDRESS_P2PKH; break;
//                 case 1: return this->base58_.ADDRESS_P2SH; break;
//                 case 2: return this->base58_.WIF; break;
//             }
//         };
//         /**************************************************/

//         /**************************************************
//          * @brief sets the networks Base58 prefix given a prefix name and byte
//          * 
//          * @param Base58PrefixType prefix
//          * @param uint8_t newByte
//          **************************************************/
//         void setBase58Prefix(Base58PrefixType prefix, uint8_t newByte)
//         {
//             if (!isLocked_) {
//                 switch (prefix) {
//                     case 0: this->base58_.ADDRESS_P2PKH = newByte; break;
//                     case 1: this->base58_.ADDRESS_P2SH = newByte; break;
//                     case 2: this->base58_.WIF = newByte; break;
//                 };
//             }
//         };
//         /**************************************************/

//         /**************************************************
//          * @brief get the networks BIP32 prefix byte given a prefix name
//          * 
//          * @param Base58PrefixType prefix
//          * @return long
//          **************************************************/
//         const long getBIP32Prefix(BIP32PrefixType prefix) const
//         {
//             switch (prefix) {
//                 case 0: return this->bip32_.PREFIX_XPUB; break;
//                 case 1: return this->bip32_.PREFIX_XPRV; break;
//             }
//         };
//         /**************************************************/

//         /**************************************************
//          * @brief sets the networks BIP32 prefix given a prefix name and byte
//          * 
//          * @param BIP32PrefixType prefix
//          * @param long newByte
//          **************************************************/
//         void setBIP32Prefix(BIP32PrefixType prefix, long newByte)
//         {
//             if (!isLocked_) {
//                 switch (prefix) {
//                     case 0: this->bip32_.PREFIX_XPUB = newByte; break;
//                     case 1: this->bip32_.PREFIX_XPRV = newByte; break;
//                 };
//             }
//         };
//         /**************************************************/

//         /**************************************************
//          * Get the network epoch.
//          *
//          * @return const char*
//          **************************************************/
//         const bool isLocked() const { return this->isLocked_; };
//         /**************************************************/

//         /**************************************************
//          * Get the network epoch.
//          *
//          * @return const char*
//          **************************************************/
//         const char* epoch() const { return this->epoch_; };
//         /**************************************************/

//         /**************************************************
//          * Get the network version as number.
//          *
//          * @return int
//          **************************************************/
//         const int version() const { return int(base58_.ADDRESS_P2PKH); }
//         /**************************************************/

// };
// /**************************************************/

// };
// };
// };

// #endif

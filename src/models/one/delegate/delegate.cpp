

#include "models/one/delegate/delegate.h"

namespace ARK
{
/*************************************************
* Constructor: default empty
**************************************************/
ARK::Delegate::Delegate()	:
		username_(),
		address_(),
		publicKey_(),
		vote_(),
		producedblocks_(),
		missedblocks_(),
		rate_(),
		approval_(),
		productivity_() {}
/*************************************************/

/*************************************************
* Constructor
**************************************************/
ARK::Delegate::Delegate(
		const char *const newUsername,
		const char *const newAddress,
		const char *const newPublicKey,
		const char *const newVote,
		int newProducedblocks,
		int newMissedblocks,
		int newRate,
		double newApproval,
		double newProductivity
)	:	address_(Address(newAddress)),
		publicKey_(Publickey(newPublicKey)),
		vote_(Balance(newVote)),
		producedblocks_(newProducedblocks),
		missedblocks_(newMissedblocks),
		rate_(newRate),
		approval_(newApproval),
		productivity_(newProductivity)
{
	strncpy(this->username_, newUsername, sizeof(username_) / sizeof(username_[0]));
}
/*************************************************/

/*************************************************
*
**************************************************/
size_t ARK::Delegate::printTo(Print &p) const
{
	size_t size = 0;
		size += p.print("username: ");
		size += p.print(this->username_);

		size += p.print("\naddress: ");
		size += p.print(this->address_.c_str());

		size += p.print("\npublicKey: ");
		size += p.print(this->publicKey_.c_str());

		size += p.print("\nvote: ");
		size += p.print(this->vote_.ark());

		size += p.print("\nproducedblocks: ");
		size += p.print(this->producedblocks_);

		size += p.print("\nmissedblocks: ");
		size += p.print(this->missedblocks_);

		size += p.print("\nrate: ");
		size += p.print(this->rate_);

		size += p.print("\napproval: ");
		size += p.print(this->approval_);

		size += p.print("%\nproductivity: ");
		size += p.print(this->productivity_);
		size += p.print("%");
	return size;
}
/*************************************************/

};

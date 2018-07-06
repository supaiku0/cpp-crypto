

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "utilities/platform.h"
#include "types/types.h"

namespace ARK
{
/*************************************************
* ARK::Transaction
**************************************************/
class Transaction :
		public Printable
{
	protected:
		Hash id_;
		char blockID_[32];
		char height_[32];
		int type_;
		char timestamp_[32];
		Balance amount_;
		Balance fee_;
		char vendorField_[64];
		Address senderId_;
		Address recipientId_;
		Publickey senderPublicKey_;
		Signature signature_;
		char confirmations_[64];

	public:
		/*************************************************
		* Default: Empty Constructor
		**************************************************/
		Transaction();
		/*************************************************/

		/*************************************************
		* Constructor
		**************************************************/
		Transaction(
				const char *const newID,
				const char *const newBlockID,
				const char *const newHeight,
				int newType,
				const char *const newTimestamp,
				const char *const newAmount,
				const char *const newFee,
				const char *const newVendorField,
				const char *const newSenderID,
				const char *const newRecipientID,
				const char *const newSenderPublickey,
				const char *const newSignature,
				const char *const newConfirmations
		);
		/*************************************************/

		/*************************************************
		* Accessors
		**************************************************/
		const Hash& id() const noexcept { return id_; };
		const char* block_id() const noexcept { return blockID_; };
		const char* height() const noexcept { return height_; };
		int type() const noexcept { return type_; };
		const char* timestamp() const noexcept { return timestamp_; };
		const Balance& amount() const noexcept { return amount_; };
		const Balance& fee() const noexcept { return fee_; };
		const char* vendor_field() const noexcept { return vendorField_; };
		const Address sender_id() const noexcept { return senderId_; };
		const Address recipient_id() const noexcept { return recipientId_; };
		const Publickey& sender_publickey() const noexcept { return senderPublicKey_; };
		const Signature signature() const noexcept { return signature_; };
		const char* confirmations() const noexcept { return confirmations_; };
		/*************************************************/

		/*************************************************
		*
		**************************************************/
		virtual size_t printTo(Print &p) const;
		/*************************************************/

};
/*************************************************/

};

#endif

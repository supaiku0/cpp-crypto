

#ifndef FEES_H
#define FEES_H

#include "utilities/platform.h"
#include "types/balance.h"
#include <cstring>

namespace ARK
{
/*************************************************
* ARK::Fees
* /api/blocks/getFees
**************************************************/
struct Fees :
		public Printable
{
	protected:
		Balance send_;
		Balance vote_;
		Balance delegate_;
		Balance secondsignature_;
		Balance multisignature_;

	public:
		/*************************************************
		* Constructor
		**************************************************/
		Fees(
			const char *const newSend,
			const char *const newVote,
			const char *const newDelegate,
			const char *const newSS,
			const char *const newMS
		);
		/*************************************************/

		/*************************************************
		* Accessors
		**************************************************/
		const Balance& send() const noexcept { return send_; }
		const Balance& vote() const noexcept { return vote_; }
		const Balance& delegate() const noexcept { return delegate_; }
		const Balance& second_signature() const noexcept { return secondsignature_; }
		const Balance& multi_signature() const noexcept { return multisignature_; }
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

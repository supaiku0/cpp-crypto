

#include <arkCrypto.h>

void createAccount()
{
	// Creates a devnet account
	uint8_t network_id = ARK::Constants::Networks::Network_ADV::devnet.pubKeyHash;

	// Creates a mainnet account
	//const auto network_id = ARK::Constants::Networks::Network_ADV::devnet.pubKeyHash;
	
	// Randomly generate a 12 word passphrase using English words
	const char* passphrase = ARK::Crypto::BIP39::generate_mnemonic().c_str();
	Serial.print("\nPassphrase: ");
	Serial.println(passphrase);
  
	const auto account = ARK::Crypto::createAccount(network_id, passphrase);
	Serial.print("\nAddress: ");
	Serial.println(account.address().c_str());

	Serial.print("\nPublic Key: ");
	Serial.println(account.public_key().c_str());
}

void setup()
{
  Serial.begin(115200);
  createAccount();
}

void loop() {}



# Arduino Builds


### requirements:

**Arduino IDE:**  
Download and install the Arduino IDE (>=1.8.5) from the following link:  
```https://www.arduino.cc/en/Main/Software```

#

### dependencies:

Using the Arduino IDE's built in Library Manager,  
install the following Libraries  
- micro-ecc
- AUnit

#

### Using with the Arduino IDE
> include the following header in your Arduino Sketch:  
```cpp
#include <arkCrypto.h>
```

#

### Arduino Example using the Adafruit Feather ESP8266

```cpp
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

void constructBalance()
{
  Balance balance("12984403000000000");
    Serial.print("\nBalance: 12984403000000000\n");
    Serial.print("\nBalance.ark: ");
    Serial.println(balance.ark());
    Serial.print("\nBalance.arktoshi: ");
    Serial.println(balance.arktoshi());
    Serial.flush();

  Balance balance2("100000000");
    Serial.print("\nBalance: 100000000\n");
    Serial.print("\nBalance.ark: ");
    Serial.println(balance2.ark());
    Serial.print("\nBalance.arktoshi: ");
    Serial.println(balance2.arktoshi());
    Serial.flush();

  Balance balance3("10000000");
    Serial.print("\nBalance: 10000000\n");
    Serial.print("\nBalance.ark: ");
    Serial.println(balance3.ark());
    Serial.print("\nBalance.arktoshi: ");
    Serial.println(balance3.arktoshi());
    Serial.flush();

  Balance balance4("10000");
    Serial.print("\nBalance: 10000\n");
    Serial.print("\nBalance.ark: ");
    Serial.println(balance4.ark());
    Serial.print("\nBalance.arktoshi: ");
    Serial.println(balance4.arktoshi());
    Serial.flush();
};

void setup()
{
    Serial.begin(115200);
    createAccount();
    constructBalance();
}

void loop() {}

```
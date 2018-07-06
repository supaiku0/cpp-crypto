

# OS (Desktop/Server)

## Using CMake

### make, build, and test
**`cd`** into **`.../cpp-crypto/`**  
then run the following commands:  

init & update micro-ecc submodule  
>`git submodule init && git submodule update`

make and build  
> `cmake . && cmake --build .`

test  
> `./bin/Ark-Cpp-Crypto-tests`

#

## Using PlatformIO

**`cd` into this directory "*.../Ark-Cpp/test*"**  
> ```cd test```

**execute the following command to upload test to your board:**  

>| board | command |
>|:-- |:-- |
>| ESP8266 | ```pio run -e esp8266 -t upload``` |
>| ESP32 | ```pio run -e esp32 -t upload``` |

> ^ the above runs the tests rooted in the following file:
> "*.../cpp-crypto/test/IoT/test_main.cpp*" 

#

### what you should see from your serial monitor

```
TestRunner started on 28 test(s).
Test crypto__create_account passed.
Test crypto__fromWIF passed.
Test crypto__generate_address passed.
Test crypto__get_private_key passed.
Test crypto__get_public_key passed.
Test crypto__toWIF passed.
Test crypto_bip39__generate_mnemonic passed.
Test model__construct_account passed.
Test model__construct_account_make passed.
Test model__construct_block passed.
Test model__construct_currency passed.
Test model__construct_delegate passed.
Test model__construct_fees passed.
Test model__construct_network passed.
Test model__construct_peer passed.
Test model__construct_transaction passed.
Test model__construct_voter passed.
Test types__construct_address passed.
Test types__construct_balance_max passed.
Test types__construct_balance_one_ark passed.
Test types__construct_balance_one_tenth_ark passed.
Test types__construct_balance_ten_thousand_arktoshi passed.
Test types__construct_hash passed.
Test types__construct_hash_empty passed.
Test types__construct_publickey passed.
Test types__construct_publickey_empty passed.
Test types__construct_signature passed.
Test types__construct_signature_empty passed.
TestRunner duration: 2.638 seconds.
TestRunner summary: 28 passed, 0 failed, 0 skipped, 0 timed out, out of 28 test(s).
```
😎👍

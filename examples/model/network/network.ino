

#include <arkCrypto.h>

/********************************************************************************
* example devnet from: api/loader/autoconfigure
*
* network:
*   {
*     "nethash":  Hash,   //  "578e820911f24e039733b45e4882b73e301f813a0d2c31330dafda84534ffa23",
*     "token":  const char*,   //  "DARK",
*     "symbol": const char*,   //  "DѦ",
*     "explorer": const char*, //  "http://dexplorer.ark.io",
*     "version":  Int,    //  30
*   }
*
********************************************************************************/
void constructNetwork()
{
  ARK::Network network(
    "578e820911f24e039733b45e4882b73e301f813a0d2c31330dafda84534ffa23",
    "DARK",
    "DѦ",
    "http://dexplorer.ark.io",
    30
  );
  Serial.print("\nOffline Instantiated Network Description\n"); 
  Serial.println(network); 
};

void setup()
{
  Serial.begin(115200);
  constructNetwork();
}

void loop() {}



#include <arkCrypto.h>

/********************************************************************************
*
* currency: 
*   {
*     "ticker": const char*,   //  "ARK",
*     "name":  const char*,    //  "ark",
*     "symbol":  const char*,  //  "Ѧ",
*   }
*
********************************************************************************/
void constructCurrency()
{
  ARK::Model::Currency currency(
    "ARK",
    "ark",
    "Ѧ"
  );
  Serial.print("\nOffline Instantiated Block Description\n"); 
  Serial.println(currency); 
};

void setup()
{
  Serial.begin(115200);
  constructCurrency();
}

void loop() {}

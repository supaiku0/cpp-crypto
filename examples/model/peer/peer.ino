

#include <arkCrypto.h>

/********************************************************************************
* example peer from: api/peers/get?ip=167.114.29.55&port=4002
*
* peer: 
*   {
*     "ip": const char*,         //  "167.114.29.55",
*     "port": int,          //  4002,
*     "version":  const char*,   //  "1.1.1",
*     "errors": int,        //  0,
*     "os": const char*,         //  "linux4.4.0-79-generic",
*     "height": const char*,     //  2467740,
*     "status": const char*,     //  "OK",
*     "delay":  int         //  9
*   }
*
********************************************************************************/
void constructPeer()
{
  ARK::Peer peer(
    "167.114.29.55",
    4002,
    "1.1.1",
    0,
    "linux4.4.0-79-generic",
    "2467740",
    "OK",
    9
  );
  Serial.print("\nOffline Instantiated Peer Description\n"); 
  Serial.println(peer); 
};

void setup()
{
  Serial.begin(115200);
  constructPeer();
}

void loop() {}

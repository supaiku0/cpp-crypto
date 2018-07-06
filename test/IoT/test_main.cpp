

#if (defined PLATFORMIO && defined UNIT_TEST)

#include <AUnit.h>

void setup() {
    Serial.begin(115200);
	while (!Serial); // for the Arduino Leonardo/Micro only
	delay(1000);
	aunit::TestRunner::setTimeout(0);
	delay(1000);
}

void loop() {
	aunit::TestRunner::run();
}

#endif

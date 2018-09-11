

#ifndef HELPERS_H
#define HELPERS_H

#include <string>
#include <cstring>


const auto ADDRESS_LENGTH = 34u;
const auto COMPRESSED_PUBLICKEY_SIZE = 33u;
const auto PRIVATEKEY_SIZE = 32u;
const auto WIF_SIZE = 52u;


#if (defined ARDUINO || defined ESP8266 || defined ESP32)

#define USE_IOT

#include <Arduino.h>
#include <pgmspace.h>

// undef the C macros to allow the C++ STL to take over
// This is to have compatibility with various board implementations of the STL
#undef min
#undef max

    template <typename T>
    std::string toString(T val) {
        return String(val).c_str();
    };

    const static inline std::string toString(uint64_t input)
    {
        std::string result;
        uint8_t base = 10;
        do {
            char c = input % base;
            input /= base;
            if (c < 10) {
                c += '0';
            } else {
                c += 'A' - 10;
            };
            result = c + result;
        } while (input);
        return result;
    }

#else

    template <typename T>
    std::string toString(T val) {
        return std::to_string(val);
    }

#endif

#endif
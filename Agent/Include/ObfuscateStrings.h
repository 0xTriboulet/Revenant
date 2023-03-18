//
// Created by 0xtriboulet on 3/17/2023.
//
// Based on: https://papers.vx-underground.org/papers/Windows/Evasion%20-%20Anti-debugging/2020-07-03%20-%20How%20to%20obfuscate%20strings%20using%20CPlusPlus%20constexpr%20Or%20how%20to%20do%20it%20correctly%20at%20compile%20time.txt

#ifndef REVENANT_OBFUSCATESTRINGS_H
#define REVENANT_OBFUSCATESTRINGS_H

#include <stdio.h>
#include <string.h>

// !!!
// CURRENTLY ONLY WORKS TO OBFUSCATE THE "Command Dispatcher..." STRING
// REQUIRES STRINGS TO BE EXACT LENGTH MATCH TO MACRO
// !!!

// Macro to compute the XOR of two characters
#define XOR_CHAR(c, k) ((c) ^ (k))

// Macro to generate a unique key based on the compilation time
#define UNIQUE_KEY() (__DATE__ __TIME__)

// Macro to XOR a string with the unique key
#define XOR_STRING(str, key) { \
    XOR_CHAR(str[0], key[0 % (sizeof(key)-1)]), \
    XOR_CHAR(str[1], key[1 % (sizeof(key)-1)]), \
    XOR_CHAR(str[2], key[2 % (sizeof(key)-1)]), \
    XOR_CHAR(str[3], key[3 % (sizeof(key)-1)]), \
    XOR_CHAR(str[4], key[4 % (sizeof(key)-1)]), \
    XOR_CHAR(str[5], key[5 % (sizeof(key)-1)]), \
    XOR_CHAR(str[6], key[6 % (sizeof(key)-1)]), \
    XOR_CHAR(str[7], key[7 % (sizeof(key)-1)]), \
    XOR_CHAR(str[8], key[8 % (sizeof(key)-1)]), \
    XOR_CHAR(str[9], key[9 % (sizeof(key)-1)]), \
    XOR_CHAR(str[10], key[10 % (sizeof(key)-1)]), \
    XOR_CHAR(str[11], key[11 % (sizeof(key)-1)]), \
    XOR_CHAR(str[12], key[12 % (sizeof(key)-1)]), \
    XOR_CHAR(str[13], key[13 % (sizeof(key)-1)]), \
    XOR_CHAR(str[14], key[14 % (sizeof(key)-1)]), \
    XOR_CHAR(str[15], key[15 % (sizeof(key)-1)]), \
    XOR_CHAR(str[16], key[16 % (sizeof(key)-1)]), \
    XOR_CHAR(str[17], key[17 % (sizeof(key)-1)]), \
    XOR_CHAR(str[18], key[18 % (sizeof(key)-1)]), \
    XOR_CHAR(str[19], key[19 % (sizeof(key)-1)]), \
    XOR_CHAR(str[20], key[20 % (sizeof(key)-1)]), \
    XOR_CHAR(str[21], key[21 % (sizeof(key)-1)]), \
    /* Add more lines depending on the maximum string length you expect. */ \
    0 \
}
void xor_decrypt(char *dst, const char *src, const char *key, size_t len);
#endif //REVENANT_OBFUSCATESTRINGS_H

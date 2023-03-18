//
// Created by 0xtriboulet on 3/17/2023.
//
// Based on: https://papers.vx-underground.org/papers/Windows/Evasion%20-%20Anti-debugging/2020-07-03%20-%20How%20to%20obfuscate%20strings%20using%20CPlusPlus%20constexpr%20Or%20how%20to%20do%20it%20correctly%20at%20compile%20time.txt

#ifndef REVENANT_OBF_STRINGS_H
#define REVENANT_OBF_STRINGS_H


// Defining the KEY based on compile time in seconds since 00:00:00, limit to 1 BYTE in size
#define KEY (((__TIME__[7] - '0') * 1 + (__TIME__[6] - '0') * 10 \
                        + (__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 \
                        + (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000) & 0xFF)

#define XOR_CHAR(c) ((c) ^ KEY)
#define XOR_STR_1(s, i) (XOR_CHAR(s[i]))
#define XOR_STR_2(s, i) XOR_STR_1(s, i), XOR_STR_1(s, i + 1)
#define XOR_STR_4(s, i) XOR_STR_2(s, i), XOR_STR_2(s, i + 2)
#define XOR_STR_8(s, i) XOR_STR_4(s, i), XOR_STR_4(s, i + 4)
#define XOR_STR_16(s, i) XOR_STR_8(s, i), XOR_STR_8(s, i + 8)
#define XOR_STR_32(s, i) XOR_STR_16(s, i), XOR_STR_16(s, i + 16)
#define XOR_STR_64(s, i) XOR_STR_32(s, i), XOR_STR_32(s, i + 32)
#define XOR_STR_128(s, i) XOR_STR_64(s, i), XOR_STR_64(s, i + 64)
#define XOR_STR_256(s, i) XOR_STR_128(s, i), XOR_STR_128(s, i + 128)
#define XOR_STR(s) ((char[]){ XOR_STR_256((s), 0), '\0' })


unsigned char * deobfuscate(unsigned char* m_data) {
    int i = 0;
    do {
        m_data[i] ^= KEY;
        i++;
    } while (m_data[i-1]);

    return m_data;
}


#endif //REVENANT_OBF_STRINGS_H

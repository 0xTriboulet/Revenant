//
// Created by 0xtriboulet on 3/17/2023.
//
#include <ObfuscateStrings.h>



void xor_decrypt(char *dst, const char *src, const char *key) {
    SIZE_T len = MAX_LENGTH;
    for (size_t i = 0; i < len; ++i) {
        dst[i] = src[i] ^ key[i % (strlen(key))];
    }
    dst[len] = '\0';
}
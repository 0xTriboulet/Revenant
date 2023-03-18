//
// Created by 0xtriboulet on 3/17/2023.
//
#include <ObfuscateStrings.h>

static inline void xor_decrypt(char *dst, const char *src, const char *key, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        dst[i] = src[i] ^ key[i % (strlen(key))];
    }
    dst[len] = '\0';
}
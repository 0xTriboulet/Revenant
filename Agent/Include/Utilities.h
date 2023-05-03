//
// Created by 0xtriboulet on 3/30/2023.
//

#ifndef REVENANT_UTILITIES_H
#define REVENANT_UTILITIES_H

#include <windows.h>

#include "Obfuscation.h"

// Macro to call rotate_left and xor_crypt
#define ROL_AND_DECRYPT(message, size, shift, output, key, key_len) do { \
    rotate_left(message, size, shift); \
    xor_dec(message, output, key, key_len); \
} while (0)

char* str_dup(const char* str);
size_t str_len(const char* str);
size_t sizeof_w(const wchar_t* str);
char** split_first_space(const char* str);
int str_cmp(const char *s1, const char *s2);
void *mem_set(void *dest, int value, size_t count);
int mem_cmp(const void *s1, const void *s2, size_t n);
void *mem_cpy(void *dest, const void *src, size_t count);
wchar_t* wide_concat(const wchar_t* str1, const wchar_t* str2);
unsigned char* obfuscate_usage(unsigned char* arr, size_t arr_size);
void rotate_left(unsigned char *data, size_t size, unsigned int bits);
char* mem_cat(const void* ptr1, size_t size1, const void* ptr2, size_t size2);

HMODULE LocalGetModuleHandle(LPCSTR moduleName);
BOOL IsStringEqual (LPCWSTR Str1, LPCWSTR Str2);

#if CONFIG_NATIVE == TRUE
void normalize_path(char* path);
#endif



#endif //REVENANT_UTILITIES_H

//
// Created by 0xtriboulet on 3/30/2023.
//

#ifndef REVENANT_UTILITIES_H
#define REVENANT_UTILITIES_H

#include <windows.h>

#include "Obfuscation.h"

// Macro to call rotate_left and xor_crypt
#define ROL_AND_DECRYPT(message, size, shift, output, key) do { \
    rotate_left(message, size, shift); \
    xor_dec(message, output, key, size); \
} while (0)


CHAR* str_dup(CONST CHAR* str);
INT lstr_lenW(CONST WCHAR* str);
SIZE_T str_len(CONST CHAR* str);
SIZE_T sizeof_w(CONST WCHAR* str);

CHAR** split_first_space(CONST CHAR* str);
INT str_cmp(CONST CHAR *s1, CONST CHAR *s2);

VOID* mem_set(VOID * dest, INT value, SIZE_T count);
INT mem_cmp(CONST VOID *s1, CONST VOID *s2, SIZE_T n);
UCHAR * obfuscate_usage(UCHAR * arr, SIZE_T arr_size);
VOID rotate_left(UCHAR * data, SIZE_T size, UINT bits);
VOID* mem_cpy_w(VOID* dest, CONST VOID* src, SIZE_T n);
VOID* mem_move(VOID* dest, CONST VOID* src, SIZE_T count);
VOID* mem_cpy(VOID * dest, CONST VOID * src, SIZE_T count);
WCHAR * wide_concat(CONST WCHAR * str1, CONST WCHAR * str2);
CHAR* mem_cat(CONST VOID* ptr1, SIZE_T size1, CONST VOID* ptr2, SIZE_T size2);
VOID HookingManager(BOOL UnHook, LPVOID pCache, HMODULE p_ntdll, SIZE_T ntdll_size);

HMODULE LocalGetModuleHandle(LPCSTR moduleName);
BOOL IsStringEqual (LPCWSTR Str1, LPCWSTR Str2);

#if CONFIG_NATIVE == TRUE
VOID normalize_path(CHAR* path);
#endif



#endif //REVENANT_UTILITIES_H

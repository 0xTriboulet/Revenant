//
// Created by 0xtriboulet on 3/19/2023.
//
#include <windows.h>

void * MemCopy(void* dest, const void* src, size_t n){
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (n--)
        *d++ = *s++;
    return dest;
}
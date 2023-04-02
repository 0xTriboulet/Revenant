//
// Created by 0xtriboulet on 3/25/2023.
//
#include "Obfuscation.h"
#include "Utilities.h"
#include <windows.h>

wchar_t *str_to_wide(const char* ascii) {
    size_t ascii_len = str_len(ascii);
    size_t wide_len = mbstowcs(NULL, ascii, ascii_len);
    if (wide_len == (size_t)-1)
        return NULL;

    wchar_t *wide = (wchar_t *)malloc((wide_len + 1) * sizeof(wchar_t));
    mbstowcs(wide, ascii, wide_len + 1);
    wide[wide_len] = L'\0';
    return wide;
}

char *xor_dec(char *_t, size_t _t_len, const char *_p, size_t _p_len) {
    for (size_t i = 0; i < _t_len; i++) _t[i] ^= _p[i % _p_len];
    return _t;
}

uint32_t crc32b(const uint8_t *str) {
    uint32_t crc = 0xFFFFFFFF;
    uint32_t byte;
    uint32_t mask;
    int i = 0x0;
    int j;

    while (str[i] != 0) {
        byte = str[i];
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEED & mask);
        }
        i++;
    }
    return ~crc;
}

void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash) {
    void *base = dll_address;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)base + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    unsigned long *p_address_of_functions = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfFunctions);
    unsigned long *p_address_of_names = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfNames);
    unsigned short *p_address_of_name_ordinals = (PWORD)((DWORD_PTR)base + export_directory->AddressOfNameOrdinals);

    for(unsigned long i = 0; i < export_directory->NumberOfNames; i++) {
        LPCSTR p_function_name = (LPCSTR)((DWORD_PTR)base + p_address_of_names[i]);
        unsigned short p_function_ordinal = (unsigned short)p_address_of_name_ordinals[i];
        unsigned long p_function_address = (unsigned long)p_address_of_functions[p_function_ordinal];

        if(function_hash == HASH(p_function_name))
            return (void *)((DWORD_PTR)base + p_function_address);
    }
    return NULL;
}

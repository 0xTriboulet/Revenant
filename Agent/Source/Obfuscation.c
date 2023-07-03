//
// Created by 0xtriboulet on 3/25/2023.
//
#include "Poly.h"
#include "Utilities.h"
#include "Obfuscation.h"

#include <windows.h>

WCHAR* str_to_wide(CONST CHAR* ascii) {

    SIZE_T ascii_len = str_len(ascii);
    SIZE_T wide_len = mbstowcs(NULL, ascii, ascii_len);
    if (wide_len == (SIZE_T)-1)
        return NULL;

    WCHAR *wide = (WCHAR *)LocalAlloc(LPTR, (wide_len + 1) * sizeof(wchar_t));
    mbstowcs(wide, ascii, wide_len + 1);
    wide[wide_len] = L'\0';
    return wide;
}

VOID xor_dec (CONST CHAR* input, CHAR* output, CONST CHAR* key, SIZE_T size) {
    SIZE_T length = size;
    INT key_len = str_len(key);

    for (int i = 0; i < length; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }
    // _tprintf("input: %s\n", input);
    // _tprintf("output: %s\n", output);
    output[length] = '\0';

}

UINT32 crc32b(CONST UINT8* str) {
    UINT32 crc = 0xFFFFFFFF;
    UINT32 byte;
    UINT32 mask;
    INT i = 0x0;
    INT j;

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


VOID* GetProcAddressByHash(VOID* dll_address, UINT32 function_hash) {
    VOID* base = dll_address;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)base + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    ULONG* p_address_of_functions = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfFunctions);
    ULONG* p_address_of_names = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfNames);
    USHORT * p_address_of_name_ordinals = (PWORD)((DWORD_PTR)base + export_directory->AddressOfNameOrdinals);

    for(ULONG i = 0; i < export_directory->NumberOfNames; i++) {
        LPCSTR p_function_name = (LPCSTR)((DWORD_PTR)base + p_address_of_names[i]);
        USHORT p_function_ordinal = (USHORT)p_address_of_name_ordinals[i];
        ULONG p_function_address = (ULONG)p_address_of_functions[p_function_ordinal];

        if(function_hash == HASH(p_function_name))
            return (VOID *)((DWORD_PTR)base + p_function_address);
    }
    return NULL;
}

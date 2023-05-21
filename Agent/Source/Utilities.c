//
// Created by 0xtriboulet on 3/30/2023.
//

#include "Config.h"
#include "Poly.h"

#include <windows.h>

VOID* mem_set(VOID * dest, INT value, SIZE_T count)
{
    UCHAR * p = dest;
    UCHAR v = (UCHAR)value;
    while (count--){
        *p++ = v;
    }
    return dest;
}


VOID* mem_cpy(VOID * dest, CONST VOID * src, SIZE_T count)
{
    UCHAR * d = (UCHAR *)dest;
    CONST UCHAR * s = (CONST UCHAR *)src;

    // Copy bytes from the source to the destination
    for (SIZE_T i = 0; i < count; i++) {
        d[i] = s[i];
    }

    return dest;
}

VOID* mem_move(VOID* dest, CONST VOID* src, SIZE_T count)
{
    UCHAR * pDest = dest;
    CONST  UCHAR * pSrc = src;
    if (pDest == pSrc)
        return dest;
    if (pDest < pSrc) {
        while (count--)
            *pDest++ = *pSrc++;
    }
    else {
        pDest += count;
        pSrc += count;
        while (count--)
            *--pDest = *--pSrc;
    }
    return dest;
}

VOID normalize_path(CHAR* path)
{
    CONST CHAR prefix[] = "\\??\\";
    CONST CHAR separator[] = "\\";
    CONST CHAR* drive_letter = strchr(path, ':');
    CHAR * p = path;

    while (*p != '\0') {
        if (*p == '/')
            *p = separator[0];
        p++;
    }
    if (drive_letter != NULL) {
        // Add the prefix for drive paths
        mem_move(path + str_len(prefix), path, str_len(path) + 1);
        mem_cpy(path, prefix, str_len(prefix));
    } else {
        // Add the prefix for non-drive paths
        CONST CHAR* unc_prefix = "\\";
        mem_move(path + str_len(prefix) + str_len(unc_prefix), path, str_len(path) + 1);
        mem_cpy(path, prefix, str_len(prefix));
        mem_cpy(path + str_len(prefix), unc_prefix, str_len(unc_prefix));
    }
}

CHAR* str_dup(CONST CHAR* str)
{
    SIZE_T len = strlen(str) + 1;
    CHAR* result = (CHAR*)LocalAlloc(LPTR, len * sizeof(CHAR));
    if (result != NULL) {
        mem_cpy(result, str, len);
    }
    return result;
}

SIZE_T str_len(CONST CHAR* str)
{
    CONST CHAR* p = str;
    while (*p != '\0') {
        p++;
    }
    return p - str;
}

CHAR** split_first_space(CONST CHAR* str)
{
    CHAR** result = (CHAR**)LocalAlloc(LPTR, 2 * sizeof(CHAR*));
    if (result == NULL) {
        return NULL;
    }

    SIZE_T len = str_len(str);
    INT space_idx = -1;
    for (INT i = 0; i < len; i++) {
        if (str[i] == ' ') {
            space_idx = i;
            break;
        }
    }

    if (space_idx == -1) {
        result[0] = str_dup(str);
        result[1] = NULL;
    } else {
        result[0] = (CHAR*)LocalAlloc(LPTR, (space_idx + 1) * sizeof(CHAR));
        result[1] = (CHAR*)LocalAlloc(LPTR, (len - space_idx) * sizeof(CHAR));
        if (result[0] == NULL || result[1] == NULL) {
            LocalFree(result[0]);
            LocalFree(result[1]);
            LocalFree(result);
            return NULL;
        }

        mem_cpy(result[0], str, space_idx);
        result[0][space_idx] = '\0';
        mem_cpy(result[1], str + space_idx + 1, len - space_idx);
    }

    return result;
}


CHAR* mem_cat(CONST VOID* ptr1, SIZE_T size1, CONST VOID* ptr2, SIZE_T size2)
{
    VOID* result = LocalAlloc(LPTR,size1 + size2);
    if (result == NULL) {
        return NULL;
    }
    mem_cpy(result, ptr1, size1);
    mem_cpy(result + size1, ptr2, size2);
    return result;
}

SIZE_T sizeof_w(CONST WCHAR* str)
{
    SIZE_T len = 0;
    while (str[len] != L'\0') {
        len++;
    }
    return (len + 1) * sizeof(wchar_t);
}

VOID* mem_cpy_w(VOID* dest, CONST VOID* src, SIZE_T n)
{
    WCHAR* pdest = (WCHAR*)dest;
    CONST WCHAR* psrc = (CONST WCHAR*)src;
    while (n-- > 0) {
        *pdest++ = *psrc++;
    }
    return dest;
}

WCHAR * wide_concat(CONST WCHAR * str1, CONST WCHAR * str2)
{
    SIZE_T len1 = wcslen(str1);
    SIZE_T len2 = wcslen(str2);
    SIZE_T len = len1 + len2;
    WCHAR* result = (WCHAR*)LocalAlloc(LPTR, (len + 1) * sizeof(WCHAR));
    if (result == NULL) {
        return NULL;
    }
    mem_cpy_w(result, str1, len1);
    mem_cpy_w(result + len1, str2, len2);
    result[len] = L'\0';
    return result;
}

INT str_cmp(CONST CHAR *s1, CONST CHAR *s2)
{
    INT i = 0;
    while (s1[i] == s2[i]) {
        if (s1[i] == '\0') {
            return 0;
        }
        i++;
    }
    return s1[i] - s2[i];
}

UCHAR * obfuscate_usage(UCHAR * arr, SIZE_T arr_size)
{
    for (SIZE_T i = 0; i < arr_size; i++) {
        arr[i]++;   // increment the value of the current item
    }

    for (SIZE_T i = 0; i < arr_size; i++) {
        arr[i]--;   // decrement the value of the current item
    }

    return arr;
}

INT mem_cmp(CONST VOID *s1, CONST VOID *s2, SIZE_T n)
{
    CONST UCHAR * p1 = (CONST UCHAR *)s1;
    CONST UCHAR * p2 = (CONST UCHAR *)s2;

    for (SIZE_T i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }

    return 0;
}

HMODULE LocalGetModuleHandle(LPCSTR moduleName){
// Heavily based on the MaldevAcademy implementation

    // Get PEB
#if CONFIG_ARCH == 64
    PPEB pPeb		= (PPEB) get_peb_64();

#elif CONFIG_ARCH == 86
    PPEB pPeb		= (PPEB) get_peb_32();
#endif

    PCWSTR wideModuleName = str_to_wide(moduleName);

    // Getting Ldr
    PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)(pPeb->Ldr);

    // Getting the first element in the linked list (contains information about the first module)
    PLDR_DATA_TABLE_ENTRY	pDte		= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
    while (pDte) {

        // If not null
        if (pDte->FullDllName.Length != 0x0) {

            // Check if both equal
            if (IsStringEqual(pDte->FullDllName.Buffer, wideModuleName)) {
                return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

            }

        }
        else {
            break;
        }

        // Next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }

    LocalFree(wideModuleName);
    return NULL;
}


BOOL IsStringEqual (LPCWSTR Str1, LPCWSTR Str2) {
// MalDev Academy

    // Zero init
    WCHAR   lStr1	[MAX_PATH] = {0};
    WCHAR   lStr2	[MAX_PATH] = {0};

    INT		len1	= lstrlenW(Str1),
            len2	= lstrlenW(Str2);

    INT		i		= 0,
            j		= 0;

    // Checking length. We dont want to overflow the buffers
    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;

    // Converting Str1 to lower case string (lStr1)
    for (i = 0; i < len1; i++){
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0'; // null terminating

    // Converting Str2 to lower case string (lStr2)
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0'; // null terminating

    // Comparing the lower-case strings
    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;

    return FALSE;
}


VOID rotate_left(UCHAR * data, SIZE_T size, UINT bits)
{
    UINT byte_shift = bits / 8;
    UINT bit_shift = bits % 8;

    UCHAR temp[size];

    for (SIZE_T i = 0; i < size; i++) {
        SIZE_T new_index = (i + byte_shift) % size;
        temp[new_index] = (data[i] << bit_shift) | (data[(i + 1) % size] >> (8 - bit_shift));
    }
    // _tprintf("data: %s\n", temp);
    // _tprintf("temp: %s\n", data);

    mem_cpy(data, temp, size);
}

//
// Created by 0xtriboulet on 3/30/2023.
//

#include <windows.h>
#include "Config.h"
#include "Poly.h"

void *mem_set(void *dest, int value, size_t count)
{
    unsigned char *p = dest;
    unsigned char v = (unsigned char)value;
    while (count--)
        *p++ = v;
    return dest;
}


void *mem_cpy(void *dest, const void *src, size_t count)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    // Copy bytes from the source to the destination
    for (size_t i = 0; i < count; i++) {
        d[i] = s[i];
    }

    return dest;
}

void *mem_move(void *dest, const void *src, size_t count)
{
    unsigned char *pDest = dest;
    const unsigned char *pSrc = src;
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

void normalize_path(char* path)
{
    const char prefix[] = "\\??\\";
    const char separator[] = "\\";
    const char* drive_letter = strchr(path, ':');
    char *p = path;

    while (*p != '\0') {
        if (*p == '/')
            *p = separator[0];
        p++;
    }
    if (drive_letter != NULL) {
        // Add the prefix for drive paths
        mem_move(path + strlen(prefix), path, strlen(path) + 1);
        mem_cpy(path, prefix, strlen(prefix));
    } else {
        // Add the prefix for non-drive paths
        const char* unc_prefix = "\\";
        mem_move(path + strlen(prefix) + strlen(unc_prefix), path, strlen(path) + 1);
        mem_cpy(path, prefix, strlen(prefix));
        mem_cpy(path + strlen(prefix), unc_prefix, strlen(unc_prefix));
    }
}

char* str_dup(const char* str) {
    size_t len = strlen(str) + 1;
    char* result = (char*)malloc(len * sizeof(char));
    if (result != NULL) {
        mem_cpy(result, str, len);
    }
    return result;
}

size_t str_len(const char* str) {
    const char* p = str;
    while (*p != '\0') {
        p++;
    }
    return p - str;
}

char** split_first_space(const char* str) {
    char** result = (char**)malloc(2 * sizeof(char*));
    if (result == NULL) {
        return NULL;
    }

    size_t len = str_len(str);
    int space_idx = -1;
    for (int i = 0; i < len; i++) {
        if (str[i] == ' ') {
            space_idx = i;
            break;
        }
    }

    if (space_idx == -1) {
        result[0] = str_dup(str);
        result[1] = NULL;
    } else {
        result[0] = (char*)malloc((space_idx + 1) * sizeof(char));
        result[1] = (char*)malloc((len - space_idx) * sizeof(char));
        if (result[0] == NULL || result[1] == NULL) {
            free(result[0]);
            free(result[1]);
            free(result);
            return NULL;
        }

        mem_cpy(result[0], str, space_idx);
        result[0][space_idx] = '\0';
        mem_cpy(result[1], str + space_idx + 1, len - space_idx);
    }

    return result;
}


char* mem_cat(const void* ptr1, size_t size1, const void* ptr2, size_t size2) {
    void* result = malloc(size1 + size2);
    if (result == NULL) {
        return NULL;
    }
    mem_cpy(result, ptr1, size1);
    mem_cpy(result + size1, ptr2, size2);
    return result;
}

size_t sizeof_w(const wchar_t* str) {
    size_t len = 0;
    while (str[len] != L'\0') {
        len++;
    }
    return (len + 1) * sizeof(wchar_t);
}

void* mem_cpy_w(void* dest, const void* src, size_t n) {
    wchar_t* pdest = (wchar_t*)dest;
    const wchar_t* psrc = (const wchar_t*)src;
    while (n-- > 0) {
        *pdest++ = *psrc++;
    }
    return dest;
}

wchar_t* wide_concat(const wchar_t* str1, const wchar_t* str2) {
    size_t len1 = wcslen(str1);
    size_t len2 = wcslen(str2);
    size_t len = len1 + len2;
    wchar_t* result = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
    if (result == NULL) {
        return NULL;
    }
    mem_cpy_w(result, str1, len1);
    mem_cpy_w(result + len1, str2, len2);
    result[len] = L'\0';
    return result;
}

int str_cmp(const char *s1, const char *s2) {
    int i = 0;
    while (s1[i] == s2[i]) {
        if (s1[i] == '\0') {
            return 0;
        }
        i++;
    }
    return s1[i] - s2[i];
}

unsigned char* obfuscate_usage(unsigned char* arr, size_t arr_size) {
    for (size_t i = 0; i < arr_size; i++) {
        arr[i]++;   // increment the value of the current item
    }

    for (size_t i = 0; i < arr_size; i++) {
        arr[i]--;   // decrement the value of the current item
    }

    return arr;
}

int mem_cmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;

    for (size_t i = 0; i < n; i++) {
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

    return NULL;
}


BOOL IsStringEqual (LPCWSTR Str1, LPCWSTR Str2) {
// MalDev Academy

    // Zero init
    WCHAR   lStr1	[MAX_PATH] = {0};
    WCHAR   lStr2	[MAX_PATH] = {0};

    int		len1	= lstrlenW(Str1),
            len2	= lstrlenW(Str2);

    int		i		= 0,
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


//
// Created by 0xtriboulet on 3/30/2023.
//

#include <windows.h>

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
    unsigned char *pDest = dest;
    const unsigned char *pSrc = src;
    while (count--)
        *pDest++ = *pSrc++;
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
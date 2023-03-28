#ifndef REVENANT_CORE_H
#define REVENANT_CORE_H

#include <windows.h>
#include "Config.h"

#if CONFIG_OBFUSCATION
void normalize_path(char* path) {
    const char prefix[] = "\\??\\";
    const char separator[] = "\\";
    const char* drive_letter = strchr(path, ':');
    char *p = path;

    int i;
    while (*p != '\0') {
        if (*p == '/')
            *p = separator[0];
        p++;
    }
    if (drive_letter != NULL) {
        // Add the prefix for drive paths
        memmove(path + strlen(prefix), path, strlen(path) + 1);
        memcpy(path, prefix, strlen(prefix));
    } else {
        // Add the prefix for non-drive paths
        const char* unc_prefix = "\\";
        memmove(path + strlen(prefix) + strlen(unc_prefix), path, strlen(path) + 1);
        memcpy(path, prefix, strlen(prefix));
        memcpy(path + strlen(prefix), unc_prefix, strlen(unc_prefix));
    }
}
#endif

#define PRINT_HEX( b, l )                               \
    _tprintf( #b ": [%d] [ ", l );                      \
    for ( int i = 0 ; i < l; i++ )                      \
    {                                                   \
        _tprintf( "%02x ", ( ( PUCHAR ) b ) [ i ] );    \
    }                                                   \
    _tprintf( "]\n" );

VOID  RvntInit();
VOID  AnonPipeRead(HANDLE hSTD_OUT_Read);
ULONG RandomNumber32(void);

#endif //REVENANT_CORE_H

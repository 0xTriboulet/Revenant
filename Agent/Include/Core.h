#ifndef REVENANT_CORE_H
#define REVENANT_CORE_H

#include <windows.h>


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

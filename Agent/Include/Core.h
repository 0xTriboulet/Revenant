#ifndef REVNT_CORE_H
#define REVNT_CORE_H

#define PRINT_HEX( b, l )                               \
    _tprintf( #b ": [%d] [ ", l );                        \
    for ( int i = 0 ; i < l; i++ )                      \
    {                                                   \
        _tprintf( "%02x ", ( ( PUCHAR ) b ) [ i ] );      \
    }                                                   \
    _tprintf( "]" );

VOID  RevntInit();

VOID  AnonPipeRead( HANDLE hSTD_OUT_Read );
ULONG RandomNumber32( VOID );

#endif
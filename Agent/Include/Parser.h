#ifndef REVNT_PARSER_H
#define REVNT_PARSER_H

#include <windows.h>

typedef struct {
    PCHAR   Original;
    PCHAR   Buffer;
    UINT32  Size;
    UINT32  Length;

    BOOL    Endian;
} PARSER, *PPARSER;

VOID  ParserNew( PPARSER parser, PVOID buffer, UINT32 size );
VOID  ParserDecrypt( PPARSER parser, PBYTE Key, PBYTE IV );
INT   ParserGetInt32( PPARSER parser );
PCHAR ParserGetBytes( PPARSER parser, PUINT32 size );
VOID  ParserDestroy( PPARSER Parser );

#endif

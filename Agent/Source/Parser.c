#include "Poly.h"
#include "Parser.h"
#include "Utilities.h"

void ParserNew( PPARSER parser, PVOID Buffer, UINT32 size ) {

    if ( parser == NULL )
        return;

    parser->Original = LocalAlloc( LPTR, size );
    mem_cpy( parser->Original, Buffer, size );
    parser->Buffer   = parser->Original;
    parser->Length   = size;
    parser->Size     = size;
}

int ParserGetInt32( PPARSER parser ) {
    INT32 intBytes = 0;

    if ( parser->Length < 4 )
        return 0;

    mem_cpy( &intBytes, parser->Buffer, 4 );

    parser->Buffer += 4;
    parser->Length -= 4;

    if ( ! parser->Endian )
        return ( INT ) intBytes;
    else
        return ( INT ) __builtin_bswap32( intBytes );
}

PCHAR ParserGetBytes( PPARSER parser, PUINT32 size ) {
    UINT32  Length  = 0;
    PCHAR   outdata = NULL;

    if ( parser->Length < 4 )
        return NULL;

    mem_cpy( &Length, parser->Buffer, 4 );
    parser->Buffer += 4;

    if ( parser->Endian )
        Length = __builtin_bswap32( Length );

    outdata = parser->Buffer;
    if ( outdata == NULL )
        return NULL;

    parser->Length -= 4;
    parser->Length -= Length;
    parser->Buffer += Length;

    if ( size != NULL )
        *size = Length;

    return outdata;
}

void ParserDestroy( PPARSER Parser ) {
    if ( Parser->Original ) {
        mem_set( Parser->Original, 0, Parser->Size );
        LocalFree( Parser->Original );
        Parser->Original = NULL;
    }
}
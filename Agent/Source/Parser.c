#include <Parser.h>

VOID ParserNew( PPARSER parser, PVOID Buffer, UINT32 size )
{
    if ( parser == NULL )
        return;

    parser->Original = LocalAlloc( LPTR, size );

    memcpy( parser->Original, Buffer, size );

    parser->Buffer   = parser->Original;
    parser->Length   = size;
    parser->Size     = size;
}

INT ParserGetInt32( PPARSER parser )
{
    INT32 intBytes = 0;

    if ( parser->Length < 4 )
        return 0;

    memcpy( &intBytes, parser->Buffer, 4 );

    parser->Buffer += 4;
    parser->Length -= 4;

    if ( ! parser->Endian )
        return ( INT ) intBytes;
    else
        return ( INT ) __builtin_bswap32( intBytes );
}

PCHAR ParserGetBytes( PPARSER parser, PUINT32 size )
{
    UINT32  Length  = 0;
    PCHAR   outdata = NULL;

    if ( parser->Length < 4 )
        return NULL;

    memcpy( &Length, parser->Buffer, 4 );
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

VOID ParserDestroy( PPARSER Parser )
{
    if ( Parser->Original )
    {
        memset( Parser->Original, 0, Parser->Size );
        LocalFree( Parser->Original );
        Parser->Original = NULL;
    }
}
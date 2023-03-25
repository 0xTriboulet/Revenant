#ifndef REVENANT_PARSER_H
#define REVENANT_PARSER_H

#include <windows.h>

typedef struct {
    PCHAR  Original;
    PCHAR  Buffer;
    UINT32 Size;
    UINT32 Length;

    BOOL   Endian;
} PARSER, *PPARSER;

void  ParserNew(PPARSER parser, PVOID buffer, UINT32 size);
void  ParserDecrypt(PPARSER parser, PBYTE Key, PBYTE IV);
int   ParserGetInt32(PPARSER parser);
PCHAR ParserGetBytes(PPARSER parser, PUINT32 size);
void  ParserDestroy(PPARSER Parser);


#endif //REVENANT_PARSER_H

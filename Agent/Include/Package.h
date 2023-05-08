#ifndef REVENANT_PACKAGE_H
#define REVENANT_PACKAGE_H

#include <windows.h>

typedef struct {
    UINT32  CommandID;
    PVOID   Buffer;
    size_t  Length;
    size_t  Size;
    BOOL    Encrypt;
} PACKAGE, *PPACKAGE;

PPACKAGE PackageCreate( UINT32 CommandID );
PPACKAGE PackageNew(void);

VOID PackageAddInt32(PPACKAGE package, UINT32 iData);
VOID PackageAddInt64(PPACKAGE Package, UINT64 dataInt);
VOID PackageAddBytes(PPACKAGE package, PUCHAR data, SIZE_T dataSize);
VOID PackageAddPad(PPACKAGE package, PUCHAR data, SIZE_T dataSize);
VOID PackageDestroy(PPACKAGE package);

BOOL PackageTransmit(PPACKAGE Package, PVOID *Response,PSIZE_T Size);

VOID PackageTransmitError(UINT32 CommandID, UINT32 ErrorCode);

#endif //REVENANT_PACKAGE_H

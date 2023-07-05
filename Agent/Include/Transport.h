#ifndef REVENANT_TRANSPORT_H
#define REVENANT_TRANSPORT_H

#include "Package.h"

#define DATA_FREE( d, l ) \
    mem_set( d, 0, l ); \
    LocalFree( d ); \
    d = NULL;

BOOL TransportInit();
BOOL TransportSend(LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize);

#endif //REVENANT_TRANSPORT_H

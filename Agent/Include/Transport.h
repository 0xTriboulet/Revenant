#ifndef REVENANT_TRANSPORT_H
#define REVENANT_TRANSPORT_H

#include "Package.h"

BOOL TransportInit();
BOOL TransportSend(LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize);

#endif //REVENANT_TRANSPORT_H

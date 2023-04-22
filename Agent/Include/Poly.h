#ifndef REVENANT_POLY_H
#define REVENANT_POLY_H

#include "Config.h"

#if CONFIG_POLYMORPHIC && (CONFIG_ARCH == 64)
#include <windows.h>
#include <tchar.h>
#include <psapi.h>
#include <time.h>

#include "Strings.h"
#include "Obfuscation.h"
#include "Utilities.h"
#include "Asm.h"
#include "Defs.h"

// Some Functionality based on C++ code from GuidedHacking

#define RAND ((((__TIME__[7] - '0') * 1 + (__TIME__[6] - '0') * 10 \
                   + (__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 \
                   + (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000) & 0xFF))

/// $$$ is the polymorphism macro
// $$$:
// push the flag register onto the stack
// push registers RCX, RDX, R8, R9 onto the stack
// set EAX to 0 (two times)
// set EBX to 0
// set EAX to 0 (two times)
// pop registers R9, R8, RDX, RCX from the stack in reverse order
// pop the flag register from the stack

#define $$$ __asm__ (   \
    "pushfq\n"          \
    "push rcx\n"        \
    "push rdx\n"        \
    "push r8\n"         \
    "push r9\n"         \
    "xor eax, eax\n"    \
    "xor eax, eax\n"    \
    "xor ebx, ebx\n"    \
    "xor eax, eax\n"    \
    "xor eax, eax\n"    \
    "pop r9\n"          \
    "pop r8\n"          \
    "pop rdx\n"         \
    "pop rcx\n"         \
    "popfq\n"           \
);


// A sequence of bytes to search for in memory
#define MARKER_BYTES "\x9C\x51\x52\x41\x50\x41\x51\x31\xC0\x31\xC0\x31\xDB\x31\xC0\x31\xC0\x41\x59\x41\x58\x5A\x59\x9D"
// The length of the marker in bytes
#define MARKER_SIZE 24
// S_MARKER_MASK is a string of characters representing which bytes in the marker to search for ("x" means search, any other character means ignore)


// assembler opcode defines for inline asm
#define ASM_OPCODE_JMP_REL        0xEB
#define ASM_OPCODE_NOP            0x90

// size of the full assembler instruction in bytes
#define ASM_INSTR_SIZE_JMP_REL    0x2
#define ASM_INSTR_SIZE_NOP        0x1

void morphModule();
void morphMemory(PBYTE pbyDst, BYTE byLength);
PVOID rev_memcpy (PBYTE dest, PBYTE src, size_t n);
PBYTE findPattern(PBYTE pData, SIZE_T uDataSize, PBYTE pPattern, PCHAR pszMask, SIZE_T uPatternSize);

#elif CONFIG_POLYMORPHIC && (CONFIG_ARCH == 86)
#include <windows.h>
#include <tchar.h>
#include <psapi.h>
#include <time.h>

#include "Strings.h"
#include "Obfuscation.h"
#include "Utilities.h"
#include "Asm.h"
#include "Defs.h"


#define RAND ((((__TIME__[7] - '0') * 1 + (__TIME__[6] - '0') * 10 \
                   + (__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 \
                   + (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000) & 0xFF))

/// $$$ is the polymorphism macro
// $$$:

#define $$$ __asm__ (   \
    "xor eax,eax\n"     \
    "xor ecx,ecx\n"     \
    "xor eax,eax\n"     \
    "xor ecx,ecx\n"     \
    "xor eax,eax\n"     \
    "xor ecx,ecx\n"     \
    "xor eax,eax\n"     \
);


// A sequence of bytes to search for in memory
#define MARKER_BYTES "\x31\xC0\x31\xC9\x31\xC0\x31\xC9\x31\xC0\x31\xC9\x31\xC0"

// The length of the marker in bytes
#define MARKER_SIZE 14

// S_MARKER_MASK is a string of characters representing which bytes in the marker to search for ("x" means search, any other character means ignore)

// assembler opcode defines for inline asm
#define ASM_OPCODE_JMP_REL        0xEB
#define ASM_OPCODE_NOP            0x90

// size of the full assembler instruction in bytes
#define ASM_INSTR_SIZE_JMP_REL    0x2
#define ASM_INSTR_SIZE_NOP        0x1

void morphModule();
void morphMemory(PBYTE pbyDst, BYTE byLength);
PVOID rev_memcpy (PBYTE dest, PBYTE src, size_t n);
PBYTE findPattern(PBYTE pData, SIZE_T uDataSize, PBYTE pPattern, PCHAR pszMask, SIZE_T uPatternSize);

#else
#define $$$ __asm__ ("nop\n");

#endif //POLY
void morphModule();

#endif //REVENANT_POLY_H

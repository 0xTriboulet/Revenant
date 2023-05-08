//
// Created by 0xtriboulet on 4/21/2023.
//

#include <windows.h>
#include <tchar.h>

#include "Asm.h"
#include "Config.h"
#include "Poly.h"

#if CONFIG_ARCH == 64
PVOID get_ntdll_64(){
    PVOID ntdll_64_addr = NULL;

    __asm__(
        ".intel_syntax noprefix;"
        "xor rax, rax;"
        "mov rax, gs:[rax+0x60];"
        "mov rax, [rax+0x18];"
        "mov rax, [rax+0x20];"
        "mov rax, [rax];"
        "mov rax, [rax+0x20];"
        :"=r" (ntdll_64_addr));

    return ntdll_64_addr;
}

PVOID get_peb_64(){
    PVOID peb = NULL;
    // DEBUGGING ONLY: PVOID alt_peb = (PEB*)(__readgsqword(0x60));
    __asm__ (
          ".intel_syntax noprefix;"
          "mov rax, gs:[0x60];" // Read the PEB address from TEB
          :"=a"(peb)
           );

    return peb;
}

#else
PVOID get_ntdll_32(){
    PVOID ntdll_32_addr = NULL;

    __asm(".intel_syntax noprefix;"
            "xor eax, eax;"
            "mov eax, fs:[eax+0x30];"
            "mov eax, [eax+0x0c];"
            "mov eax, [eax+0x1c];"
            "mov eax, [eax+0x8];"
            :"=r" (ntdll_32_addr));
    return ntdll_32_addr;
}

PVOID get_peb_32(){
    PVOID peb = NULL;

    __asm__( ".intel_syntax noprefix;"
            "mov eax, fs:[0x30];" // Read the PEB address from TEB
            :"=a"(peb)
            );
    return peb;
}
#endif
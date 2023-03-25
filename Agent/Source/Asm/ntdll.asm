section .text

global get_ntdll_32
global get_ntdll_64

get_ntdll_32:
    xor eax, eax
    mov eax, [fs:eax+0x30]
    mov eax, [eax+0ch]
    mov eax, [eax+1ch]
    mov eax, [eax]
    mov eax, [eax+1ch]
    ret

get_ntdll_64:
    xor rax, rax
    mov rax, [gs:rax+0x60]
    mov rax, [rax+0x18]
    mov rax, [rax+0x20]
    mov rax, [rax]
    mov rax, [rax+0x20]
    ret

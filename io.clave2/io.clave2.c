#include <Windows.h>
#include "io.clave2.emulator.h"
#include "io.clave2.hooks.h"
#include "../kitchen_sink/kitchen_sink.h"
#pragma comment(lib,"dev.kitchen_sink.lib")

__declspec(dllexport) void io_clave2() {}


// Entry-Point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DBG_printfA("[io.clave2]: LOADING...");
        if (!InitClave2EmuWindows("C:\\ez2emu\\ez2emu.ini") || !InitHooks()) {
            DBG_printfA("[io.clave2]: FAIL!");
            return FALSE;
        }
        DBG_printfA("[io.clave2]: LOADED!");
    }
    return TRUE;
}




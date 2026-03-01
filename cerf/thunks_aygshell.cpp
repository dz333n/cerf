#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* AYGSHELL.DLL thunks - WinCE Shell Helper Library.
   Most functions deal with WinCE-specific UI (SIP, fullscreen PDA, menu bars)
   and can be safely stubbed since we run on a desktop. */
#include "win32_thunks.h"
#include <cstdio>

void Win32Thunks::RegisterAygshellHandlers() {
    Thunk("SHHandleWMSettingChange", [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Handles WM_SETTINGCHANGE for SIP awareness - not needed on desktop */
        regs[0] = 0; return true;
    });
    Thunk("SHHandleWMActivate", [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Handles WM_ACTIVATE for SIP awareness - not needed on desktop */
        regs[0] = 0; return true;
    });
    Thunk("SHInitDialog", [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Initializes WinCE dialog for fullscreen/SIP - not needed on desktop */
        regs[0] = 1; return true;
    });
    Thunk("SHFullScreen", [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Controls taskbar/SIP visibility on WinCE - not needed on desktop */
        regs[0] = 1; return true;
    });
    Thunk("SHCreateMenuBar", [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Creates WinCE-style menu bar (softkeys) - stub as not applicable */
        regs[0] = 0; return true;
    });
    Thunk("SHSipPreference", [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Show/hide Soft Input Panel - not needed on desktop */
        regs[0] = 1; return true;
    });
    Thunk("SHRecognizeGesture", [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Gesture recognition (tap-and-hold etc.) - stub, return no gesture */
        regs[0] = 0; return true;
    });
    Thunk("SHSendBackToFocusWindow", [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });
    Thunk("SHSetAppKeyWndAssoc", [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Associates hardware buttons with windows - not needed */
        regs[0] = 1; return true;
    });
    Thunk("SHDoneButton", [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Show/hide Done button on WinCE caption bar */
        regs[0] = 1; return true;
    });
    Thunk("SHSipInfo", [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Query/set SIP info - return failure so apps don't expect SIP data */
        regs[0] = 0; return true;
    });
    Thunk("SHNotificationAdd", [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] SHNotificationAdd -> stub\n");
        regs[0] = 1; return true;
    });
    Thunk("SHNotificationRemove", [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });
    Thunk("SHNotificationUpdate", [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });
}

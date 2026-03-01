/* Menu thunks: Create, Append, Enable, Check, Track, Load */
#include "win32_thunks.h"
#include <cstdio>

void Win32Thunks::RegisterMenuHandlers() {
    Thunk("CreateMenu", 851, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateMenu(); return true;
    });
    Thunk("CreatePopupMenu", 852, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreatePopupMenu(); return true;
    });
    Thunk("DestroyMenu", 844, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DestroyMenu((HMENU)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("GetSubMenu", 855, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetSubMenu((HMENU)(intptr_t)(int32_t)regs[0], regs[1]); return true;
    });
    Thunk("AppendMenuW", 842, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring text = ReadWStringFromEmu(mem, regs[3]);
        regs[0] = AppendMenuW((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2],
            (regs[1] & MF_STRING) ? text.c_str() : (LPCWSTR)(uintptr_t)regs[3]);
        return true;
    });
    Thunk("EnableMenuItem", 847, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = EnableMenuItem((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2]); return true;
    });
    Thunk("CheckMenuItem", 848, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = CheckMenuItem((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2]); return true;
    });
    Thunk("CheckMenuRadioItem", 849, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = CheckMenuRadioItem((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0));
        return true;
    });
    Thunk("DrawMenuBar", 856, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DrawMenuBar((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("LoadMenuW", 846, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)LoadMenuW((HINSTANCE)(intptr_t)(int32_t)regs[0], MAKEINTRESOURCEW(regs[1]));
        return true;
    });
    Thunk("TrackPopupMenuEx", 845, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = TrackPopupMenuEx((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3],
            (HWND)(intptr_t)(int32_t)ReadStackArg(regs, mem, 0), NULL);
        return true;
    });
}

/* Input thunks: cursor, keyboard, timer, focus, capture */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterInputHandlers() {
    Thunk("SetTimer", 875, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        UINT_PTR nIDEvent = regs[1]; UINT uElapse = regs[2]; uint32_t arm_timerproc = regs[3];
        LOG(API, "[API] SetTimer(hwnd=0x%p, id=0x%X, elapse=%u, timerproc=0x%08X)\n",
            hw, (uint32_t)nIDEvent, uElapse, arm_timerproc);
        if (arm_timerproc != 0) arm_timer_callbacks[nIDEvent] = arm_timerproc;
        regs[0] = (uint32_t)(uintptr_t)SetTimer(hw, nIDEvent, uElapse, NULL);
        return true;
    });
    Thunk("KillTimer", 876, [](uint32_t* regs, EmulatedMemory&) -> bool {
        arm_timer_callbacks.erase(regs[1]);
        regs[0] = KillTimer((HWND)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    });
    Thunk("GetKeyState", 860, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)GetKeyState(regs[0]); return true;
    });
    Thunk("GetAsyncKeyState", 826, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)GetAsyncKeyState(regs[0]); return true;
    });
    Thunk("GetDoubleClickTime", 888, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetDoubleClickTime(); return true;
    });
    Thunk("GetCursorPos", 734, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        POINT pt; GetCursorPos(&pt);
        mem.Write32(regs[0], pt.x); mem.Write32(regs[0]+4, pt.y);
        regs[0] = 1; return true;
    });
    Thunk("SetCursorPos", 736, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SetCursorPos(regs[0], regs[1]); return true;
    });
    Thunk("ShowCursor", 737, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ShowCursor(regs[0]); return true;
    });
    Thunk("SetFocus", 704, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        LOG(API, "[API] SetFocus(0x%p)\n", hw);
        regs[0] = (uint32_t)(uintptr_t)SetFocus(hw); return true;
    });
    Thunk("GetFocus", 705, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetFocus(); return true;
    });
    Thunk("GetForegroundWindow", 701, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetForegroundWindow(); return true;
    });
    Thunk("SetForegroundWindow", 702, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SetForegroundWindow((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("SetActiveWindow", 703, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)SetActiveWindow((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("GetActiveWindow", 706, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetActiveWindow(); return true;
    });
    Thunk("SetCapture", 708, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)SetCapture((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("ReleaseCapture", 709, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ReleaseCapture(); return true;
    });
    Thunk("GetCapture", 707, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetCapture(); return true;
    });
    Thunk("SetCursor", 682, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)SetCursor((HCURSOR)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("LoadCursorW", 683, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)LoadCursorW((HINSTANCE)(intptr_t)(int32_t)regs[0], MAKEINTRESOURCEW(regs[1]));
        return true;
    });
    Thunk("DrawIconEx", 726, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        int xLeft = (int)regs[1], yTop = (int)regs[2];
        HICON hIcon = (HICON)(intptr_t)(int32_t)regs[3];
        int cxWidth = (int)ReadStackArg(regs, mem, 0);
        int cyWidth = (int)ReadStackArg(regs, mem, 1);
        UINT istepIfAniCur = ReadStackArg(regs, mem, 2);
        HBRUSH hbrFlicker = (HBRUSH)(intptr_t)(int32_t)ReadStackArg(regs, mem, 3);
        UINT diFlags = ReadStackArg(regs, mem, 4);
        regs[0] = DrawIconEx(hdc, xLeft, yTop, hIcon, cxWidth, cyWidth,
                              istepIfAniCur, hbrFlicker, diFlags);
        return true;
    });
    Thunk("LoadIconW", 728, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)LoadIconW((HINSTANCE)(intptr_t)(int32_t)regs[0], MAKEINTRESOURCEW(regs[1]));
        return true;
    });

    // Ordinal-only entries (no handler, just register the ordinal mapping)
    ThunkOrdinal("ClipCursor", 731);
    ThunkOrdinal("GetCursor", 733);
    ThunkOrdinal("CreateCursor", 722);
    Thunk("CreateIconIndirect", 723, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* 32-bit ICONINFO: fIcon(4), xHotspot(4), yHotspot(4), hbmMask(4), hbmColor(4) = 20 bytes */
        uint32_t addr = regs[0];
        ICONINFO ii = {};
        ii.fIcon    = mem.Read32(addr + 0);
        ii.xHotspot = mem.Read32(addr + 4);
        ii.yHotspot = mem.Read32(addr + 8);
        ii.hbmMask  = (HBITMAP)(intptr_t)(int32_t)mem.Read32(addr + 12);
        ii.hbmColor = (HBITMAP)(intptr_t)(int32_t)mem.Read32(addr + 16);
        regs[0] = (uint32_t)(uintptr_t)CreateIconIndirect(&ii);
        return true;
    });
    ThunkOrdinal("DestroyCursor", 724);
    Thunk("DestroyIcon", 725, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DestroyIcon((HICON)(intptr_t)(int32_t)regs[0]); return true;
    });
    ThunkOrdinal("GetClipCursor", 732);
    ThunkOrdinal("LoadAcceleratorsW", 94);
}

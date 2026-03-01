/* Window thunks: RegisterClass, CreateWindowEx, Show/Move/Destroy */
#include "win32_thunks.h"
#include <cstdio>
#include <commctrl.h>

void Win32Thunks::RegisterWindowHandlers() {
    Thunk("RegisterClassW", 95, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t arm_wndproc = mem.Read32(regs[0] + 4);
        WNDCLASSW wc = {};
        wc.style = mem.Read32(regs[0]); wc.lpfnWndProc = EmuWndProc;
        wc.cbClsExtra = mem.Read32(regs[0]+8); wc.cbWndExtra = mem.Read32(regs[0]+12);
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hIcon = (HICON)(intptr_t)(int32_t)mem.Read32(regs[0]+20);
        wc.hCursor = (HCURSOR)(intptr_t)(int32_t)mem.Read32(regs[0]+24);
        wc.hbrBackground = (HBRUSH)(intptr_t)(int32_t)mem.Read32(regs[0]+28);
        std::wstring className = ReadWStringFromEmu(mem, mem.Read32(regs[0]+36));
        wc.lpszClassName = className.c_str();
        arm_wndprocs[className] = arm_wndproc;
        printf("[THUNK] RegisterClassW: '%ls' (ARM WndProc=0x%08X)\n", className.c_str(), arm_wndproc);
        regs[0] = (uint32_t)RegisterClassW(&wc); return true;
    });
    Thunk("CreateWindowExW", 246, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t exStyle = regs[0];
        std::wstring className = ReadWStringFromEmu(mem, regs[1]);
        std::wstring windowName = ReadWStringFromEmu(mem, regs[2]);
        uint32_t style = regs[3];
        int x=(int)ReadStackArg(regs,mem,0), y=(int)ReadStackArg(regs,mem,1);
        int w=(int)ReadStackArg(regs,mem,2), h=(int)ReadStackArg(regs,mem,3);
        HWND parent = (HWND)(intptr_t)(int32_t)ReadStackArg(regs,mem,4);
        HMENU menu_h = (HMENU)(intptr_t)(int32_t)ReadStackArg(regs,mem,5);
        exStyle &= 0x0FFFFFFF;
        bool is_toplevel = (parent == NULL && !(style & WS_CHILD));
        if (is_toplevel) {
            RECT wa; SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
            int bw = GetSystemMetrics(SM_CXBORDER), bh = GetSystemMetrics(SM_CYBORDER);
            x = wa.left-bw; y = wa.top-bh;
            w = (wa.right-wa.left)+bw*2; h = (wa.bottom-wa.top)+bh*2;
            exStyle |= WS_EX_APPWINDOW;
        } else {
            if (x==(int)0x80000000) x=CW_USEDEFAULT; if (y==(int)0x80000000) y=CW_USEDEFAULT;
            if (w==(int)0x80000000||w==0) w=320; if (h==(int)0x80000000||h==0) h=240;
        }
        printf("[THUNK] CreateWindowExW: class='%ls' title='%ls' style=0x%08X size=(%dx%d)\n", className.c_str(), windowName.c_str(), style, w, h);
        HWND hwnd = CreateWindowExW(exStyle, className.c_str(), windowName.c_str(), style, x, y, w, h, parent, menu_h, GetModuleHandleW(NULL), NULL);
        if (hwnd) {
            auto it = arm_wndprocs.find(className);
            if (it != arm_wndprocs.end()) hwnd_wndproc_map[hwnd] = it->second;
            if (is_toplevel) {
                if (!windowName.empty()) SetWindowTextW(hwnd, windowName.c_str());
                HICON hIcon = LoadIconW(NULL, IDI_APPLICATION);
                SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
                SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            }
        }
        regs[0] = (uint32_t)(uintptr_t)hwnd; return true;
    });
    Thunk("ShowWindow", 266, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        if (hw == NULL && regs[1] == 5) { regs[0] = 0; return true; }
        regs[0] = ShowWindow(hw, regs[1]); return true;
    });
    Thunk("UpdateWindow", 267, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = UpdateWindow((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("DestroyWindow", 265, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = DestroyWindow((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("SetWindowPos", 247, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = SetWindowPos((HWND)(intptr_t)(int32_t)regs[0], (HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3],
            ReadStackArg(regs,mem,0), ReadStackArg(regs,mem,1), ReadStackArg(regs,mem,2)); return true;
    });
    Thunk("MoveWindow", 272, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = MoveWindow((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs,mem,0), ReadStackArg(regs,mem,1)); return true;
    });
    Thunk("BringWindowToTop", 275, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = BringWindowToTop((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("GetWindow", 251, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)(uintptr_t)GetWindow((HWND)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("SetParent", 268, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)(uintptr_t)SetParent((HWND)(intptr_t)(int32_t)regs[0], (HWND)(intptr_t)(int32_t)regs[1]); return true; });
    Thunk("MapWindowPoints", 284, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("GetClassInfoW", 878, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("UnregisterClassW", 884, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("CallWindowProcW", 285, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)DefWindowProcW((HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3], ReadStackArg(regs,mem,0)); return true;
    });
    Thunk("ScrollWindowEx", 289, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("SetScrollInfo", 279, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    thunk_handlers["SetScrollPos"] = thunk_handlers["SetScrollInfo"];
    thunk_handlers["SetScrollRange"] = thunk_handlers["SetScrollInfo"];
    thunk_handlers["GetScrollInfo"] = thunk_handlers["SetScrollInfo"];
    Thunk("EnumWindows", 291, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    thunk_handlers["GetWindowThreadProcessId"] = thunk_handlers["EnumWindows"];
    Thunk("RegisterWindowMessageW", 891, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring msg_name = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = RegisterWindowMessageW(msg_name.c_str()); return true;
    });
    Thunk("GetDesktopWindow", 1397, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=(uint32_t)(uintptr_t)GetDesktopWindow(); return true; });
    Thunk("FindWindowW", 286, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring cn = ReadWStringFromEmu(mem, regs[0]), wn = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)(uintptr_t)FindWindowW(regs[0] ? cn.c_str() : NULL, regs[1] ? wn.c_str() : NULL);
        return true;
    });
    Thunk("WindowFromPoint", 252, [](uint32_t* regs, EmulatedMemory&) -> bool {
        POINT pt = { (LONG)regs[0], (LONG)regs[1] };
        regs[0] = (uint32_t)(uintptr_t)WindowFromPoint(pt); return true;
    });
    Thunk("ClientToScreen", 254, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        POINT pt; pt.x = mem.Read32(regs[1]); pt.y = mem.Read32(regs[1]+4);
        BOOL ret = ClientToScreen((HWND)(intptr_t)(int32_t)regs[0], &pt);
        mem.Write32(regs[1], pt.x); mem.Write32(regs[1]+4, pt.y);
        regs[0] = ret; return true;
    });
    Thunk("ScreenToClient", 255, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        POINT pt; pt.x = mem.Read32(regs[1]); pt.y = mem.Read32(regs[1]+4);
        BOOL ret = ScreenToClient((HWND)(intptr_t)(int32_t)regs[0], &pt);
        mem.Write32(regs[1], pt.x); mem.Write32(regs[1]+4, pt.y);
        regs[0] = ret; return true;
    });
}

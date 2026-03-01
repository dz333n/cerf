#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Common controls thunks: InitCommonControls*, ImageList_* */
#include "../win32_thunks.h"
#include <cstdio>
#include <commctrl.h>

void Win32Thunks::RegisterCommctrlHandlers() {
    Thunk("InitCommonControlsEx", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t icc_addr = regs[0];
        INITCOMMONCONTROLSEX icc = {};
        icc.dwSize = sizeof(icc);
        icc.dwICC = icc_addr ? mem.Read32(icc_addr + 4) : ICC_WIN95_CLASSES;
        BOOL ret = InitCommonControlsEx(&icc);
        printf("[THUNK] InitCommonControlsEx(dwICC=0x%X) -> %d\n", icc.dwICC, ret);
        regs[0] = ret;
        return true;
    });
    Thunk("InitCommonControls", [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] InitCommonControls()\n");
        InitCommonControls(); regs[0] = 0; return true;
    });
    Thunk("ImageList_Create", 742, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)(uintptr_t)ImageList_Create(regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0));
        return true;
    });
    Thunk("ImageList_Destroy", 743, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_Destroy((HIMAGELIST)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("ImageList_Add", 738, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_Add((HIMAGELIST)(intptr_t)(int32_t)regs[0],
            (HBITMAP)(intptr_t)(int32_t)regs[1], (HBITMAP)(intptr_t)(int32_t)regs[2]);
        return true;
    });
    Thunk("ImageList_Draw", 748, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = ImageList_Draw((HIMAGELIST)(intptr_t)(int32_t)regs[0], regs[1],
            (HDC)(intptr_t)(int32_t)regs[2], regs[3], ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1));
        return true;
    });
    Thunk("ImageList_DrawEx", 749, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = ImageList_DrawEx((HIMAGELIST)(intptr_t)(int32_t)regs[0], regs[1],
            (HDC)(intptr_t)(int32_t)regs[2], regs[3],
            ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1), ReadStackArg(regs, mem, 2),
            ReadStackArg(regs, mem, 3), ReadStackArg(regs, mem, 4), ReadStackArg(regs, mem, 5));
        return true;
    });
    Thunk("ImageList_GetImageCount", 756, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_GetImageCount((HIMAGELIST)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("ImageList_LoadImage", 758, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], lpbmp = regs[1], cx = regs[2], cGrow = regs[3];
        COLORREF crMask = ReadStackArg(regs, mem, 0);
        UINT uType = ReadStackArg(regs, mem, 1);
        UINT uFlags = ReadStackArg(regs, mem, 2);
        printf("[THUNK] ImageList_LoadImage(0x%08X, %d, cx=%d, cGrow=%d, crMask=0x%X, type=%d, flags=0x%X)\n",
               hmod, lpbmp, cx, cGrow, crMask, uType, uFlags);
        HMODULE native_mod = NULL;
        bool is_arm = (hmod == emu_hinstance);
        for (auto& pair : loaded_dlls) { if (pair.second.base_addr == hmod) { is_arm = true; break; } }
        if (is_arm) native_mod = GetNativeModuleForResources(hmod);
        else native_mod = (HMODULE)(intptr_t)(int32_t)hmod;
        HIMAGELIST h = native_mod ? ImageList_LoadImageW(native_mod, MAKEINTRESOURCEW(lpbmp), cx, cGrow, crMask, uType, uFlags) : NULL;
        regs[0] = (uint32_t)(uintptr_t)h;
        return true;
    });
    Thunk("ImageList_GetIconSize", 755, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int cx, cy; BOOL ret = ImageList_GetIconSize((HIMAGELIST)(intptr_t)(int32_t)regs[0], &cx, &cy);
        if (regs[1]) mem.Write32(regs[1], cx); if (regs[2]) mem.Write32(regs[2], cy);
        regs[0] = ret; return true;
    });
    /* WinCE CommandBar/CommandBands — these are CE-specific controls with no desktop equivalent */
    Thunk("CommandBar_GetMenu", [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] CommandBar_GetMenu(hwndCB=0x%08X, iButton=%d) -> NULL (stub)\n", regs[0], regs[1]);
        regs[0] = 0; return true;
    });
    Thunk("CommandBands_AddBands", [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] CommandBands_AddBands(...) -> FALSE (stub)\n");
        regs[0] = 0; return true;
    });
    Thunk("CommandBands_GetCommandBar", [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] CommandBands_GetCommandBar(hwndCmdBands=0x%08X, uBand=%d) -> NULL (stub)\n", regs[0], regs[1]);
        regs[0] = 0; return true;
    });
    Thunk("CommandBands_AddAdornments", [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] CommandBands_AddAdornments(...) -> FALSE (stub)\n");
        regs[0] = 0; return true;
    });
    Thunk("CommandBands_GetRestoreInformation", [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] CommandBands_GetRestoreInformation(...) -> FALSE (stub)\n");
        regs[0] = 0; return true;
    });
}

/* Menu thunks: Create, Append, Enable, Check, Track, Load */
#include "../win32_thunks.h"
#include "../../log.h"
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
    Thunk("InsertMenuW", 841, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HMENU hMenu = (HMENU)(intptr_t)(int32_t)regs[0];
        UINT uPosition = regs[1], uFlags = regs[2], uIDNewItem = regs[3];
        uint32_t lpNewItem = ReadStackArg(regs, mem, 0);
        LPCWSTR str = NULL;
        std::wstring text;
        if ((uFlags & MF_STRING) && lpNewItem) {
            text = ReadWStringFromEmu(mem, lpNewItem);
            str = text.c_str();
        }
        regs[0] = InsertMenuW(hMenu, uPosition, uFlags, uIDNewItem, str);
        return true;
    });
    Thunk("DeleteMenu", 850, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DeleteMenu((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2]);
        return true;
    });
    /* SetMenuItemInfoW — WinCE MENUITEMINFOW is 44 bytes (32-bit pointers):
       +0 cbSize, +4 fMask, +8 fType, +12 fState, +16 wID,
       +20 hSubMenu(32), +24 hbmpChecked(32), +28 hbmpUnchecked(32),
       +32 dwItemData(32), +36 dwTypeData(32), +40 cch */
    Thunk("SetMenuItemInfoW", 853, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HMENU hMenu = (HMENU)(intptr_t)(int32_t)regs[0];
        UINT uItem = regs[1];
        BOOL fByPosition = regs[2];
        uint32_t pMii = regs[3];
        MENUITEMINFOW mii = {};
        mii.cbSize = sizeof(MENUITEMINFOW);
        mii.fMask = mem.Read32(pMii + 4);
        mii.fType = mem.Read32(pMii + 8);
        mii.fState = mem.Read32(pMii + 12);
        mii.wID = mem.Read32(pMii + 16);
        mii.hSubMenu = (HMENU)(intptr_t)(int32_t)mem.Read32(pMii + 20);
        mii.hbmpChecked = (HBITMAP)(intptr_t)(int32_t)mem.Read32(pMii + 24);
        mii.hbmpUnchecked = (HBITMAP)(intptr_t)(int32_t)mem.Read32(pMii + 28);
        mii.dwItemData = mem.Read32(pMii + 32);
        std::wstring text;
        uint32_t typeData = mem.Read32(pMii + 36);
        if ((mii.fMask & MIIM_STRING) || ((mii.fMask & MIIM_TYPE) && !(mii.fType & MFT_SEPARATOR))) {
            if (typeData) {
                text = ReadWStringFromEmu(mem, typeData);
                mii.dwTypeData = const_cast<LPWSTR>(text.c_str());
                mii.cch = (UINT)text.size();
            }
        }
        BOOL ret = SetMenuItemInfoW(hMenu, uItem, fByPosition, &mii);
        LOG(THUNK, "[THUNK] SetMenuItemInfoW(0x%08X, %u, %d) -> %d\n",
            (uint32_t)(uintptr_t)hMenu, uItem, fByPosition, ret);
        regs[0] = ret;
        return true;
    });
}

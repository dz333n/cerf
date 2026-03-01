#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Shell thunks: ShellExecuteEx, Shell_NotifyIcon, SHGetSpecialFolderPath */
#include "../win32_thunks.h"
#include <cstdio>
#include <shellapi.h>
#include <vector>

void Win32Thunks::RegisterShellHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            printf("[THUNK] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    Thunk("SHGetSpecialFolderPath", 295, stub0("SHGetSpecialFolderPath"));
    Thunk("SHLoadDIBitmap", 487, stub0("SHLoadDIBitmap"));
    ThunkOrdinal("SHCreateShortcut", 484);
    Thunk("ShellExecuteEx", 480, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t sei_addr = regs[0];
        if (!sei_addr) { regs[0] = 0; SetLastError(ERROR_INVALID_PARAMETER); return true; }
        /* WinCE SHELLEXECUTEINFO layout (all 32-bit pointers):
           0x00 cbSize, 0x04 fMask, 0x08 hwnd, 0x0C lpVerb, 0x10 lpFile,
           0x14 lpParameters, 0x18 lpDirectory, 0x1C nShow, 0x20 hInstApp */
        uint32_t fMask     = mem.Read32(sei_addr + 0x04);
        uint32_t hwnd_val  = mem.Read32(sei_addr + 0x08);
        uint32_t verb_ptr  = mem.Read32(sei_addr + 0x0C);
        uint32_t file_ptr  = mem.Read32(sei_addr + 0x10);
        uint32_t params_ptr= mem.Read32(sei_addr + 0x14);
        uint32_t dir_ptr   = mem.Read32(sei_addr + 0x18);
        int nShow          = (int)mem.Read32(sei_addr + 0x1C);
        std::wstring verb, file, params, dir;
        if (verb_ptr) verb = ReadWStringFromEmu(mem, verb_ptr);
        if (file_ptr) file = ReadWStringFromEmu(mem, file_ptr);
        if (params_ptr) params = ReadWStringFromEmu(mem, params_ptr);
        if (dir_ptr) dir = ReadWStringFromEmu(mem, dir_ptr);
        printf("[THUNK] ShellExecuteEx(verb='%ls', file='%ls', params='%ls', dir='%ls', nShow=%d)\n",
               verb.c_str(), file.c_str(), params.c_str(), dir.c_str(), nShow);
        SHELLEXECUTEINFOW native_sei = {};
        native_sei.cbSize = sizeof(SHELLEXECUTEINFOW);
        native_sei.fMask = fMask;
        native_sei.hwnd = (HWND)(intptr_t)(int32_t)hwnd_val;
        native_sei.lpVerb = verb.empty() ? NULL : verb.c_str();
        native_sei.lpFile = file.empty() ? NULL : file.c_str();
        native_sei.lpParameters = params.empty() ? NULL : params.c_str();
        native_sei.lpDirectory = dir.empty() ? NULL : dir.c_str();
        native_sei.nShow = nShow;
        BOOL ret = ShellExecuteExW(&native_sei);
        mem.Write32(sei_addr + 0x20, (uint32_t)(uintptr_t)native_sei.hInstApp);
        if (fMask & SEE_MASK_NOCLOSEPROCESS)
            mem.Write32(sei_addr + 0x38, (uint32_t)(uintptr_t)native_sei.hProcess);
        printf("[THUNK]   -> %s\n", ret ? "OK" : "FAILED");
        regs[0] = ret;
        return true;
    });
    Thunk("Shell_NotifyIcon", 481, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        DWORD dwMessage = regs[0];
        uint32_t nid_addr = regs[1];
        if (!nid_addr) { regs[0] = 0; return true; }
        /* WinCE NOTIFYICONDATA (32-bit):
           0x00 cbSize, 0x04 hWnd, 0x08 uID, 0x0C uFlags,
           0x10 uCallbackMessage, 0x14 hIcon, 0x18 szTip[64] (128 bytes) */
        NOTIFYICONDATAW nid = {};
        nid.cbSize = sizeof(NOTIFYICONDATAW);
        nid.hWnd = (HWND)(intptr_t)(int32_t)mem.Read32(nid_addr + 0x04);
        nid.uID = mem.Read32(nid_addr + 0x08);
        nid.uFlags = mem.Read32(nid_addr + 0x0C);
        nid.uCallbackMessage = mem.Read32(nid_addr + 0x10);
        nid.hIcon = (HICON)(intptr_t)(int32_t)mem.Read32(nid_addr + 0x14);
        for (int i = 0; i < 63; i++) {
            wchar_t c = (wchar_t)mem.Read16(nid_addr + 0x18 + i * 2);
            nid.szTip[i] = c;
            if (c == 0) break;
        }
        nid.szTip[63] = 0;
        printf("[THUNK] Shell_NotifyIcon(msg=%d, uID=%d, tip='%ls')\n",
               dwMessage, nid.uID, nid.szTip);
        BOOL ret = Shell_NotifyIconW(dwMessage, &nid);
        regs[0] = ret;
        return true;
    });
    Thunk("SHGetFileInfo", 482, [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] SHGetFileInfo(pszPath=0x%08X, attrs=0x%X, psfi=0x%08X, cbFileInfo=%d) -> 0 (stub)\n",
               regs[0], regs[1], regs[2], regs[3]);
        regs[0] = 0;
        return true;
    });
    ThunkOrdinal("GetSaveFileNameW", 489);
}

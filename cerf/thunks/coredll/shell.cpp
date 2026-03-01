#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Shell thunks: ShellExecuteEx, Shell_NotifyIcon, SHGetSpecialFolderPath,
   GetOpenFileNameW/GetSaveFileNameW (coredll re-exports from commdlg),
   SH* functions (coredll re-exports from ceshell/aygshell) */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <shellapi.h>

void Win32Thunks::RegisterShellHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(THUNK, "[THUNK] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    /* Helper: forward a coredll re-export to the real ARM DLL.
       This mirrors what real coredll does: LoadLibrary + GetProcAddress + call. */
    auto forwardToArm = [this](const char* dll, const char* func, int nargs) -> ThunkHandler {
        return [this, dll, func, nargs](uint32_t* regs, EmulatedMemory& mem) -> bool {
            LoadedDll* mod = LoadArmDll(dll);
            if (mod && callback_executor) {
                uint32_t addr = PELoader::ResolveExportName(mem, mod->pe_info, func);
                if (addr) {
                    LOG(THUNK, "[THUNK] %s -> forwarding to ARM %s!%s @ 0x%08X\n", func, dll, func, addr);
                    uint32_t args[8] = {};
                    for (int i = 0; i < nargs && i < 4; i++) args[i] = regs[i];
                    for (int i = 4; i < nargs; i++) args[i] = ReadStackArg(regs, mem, i - 4);
                    regs[0] = callback_executor(addr, args, nargs);
                    return true;
                }
            }
            LOG(THUNK, "[THUNK] %s -> %s not available, stub returning 0\n", func, dll);
            regs[0] = 0;
            return true;
        };
    };
    Thunk("SHGetSpecialFolderPath", 295, stub0("SHGetSpecialFolderPath"));
    Thunk("SHLoadDIBitmap", 487, stub0("SHLoadDIBitmap"));
    /* SHCreateShortcut(lpszShortcut, lpszTarget) — forward to ceshell.dll */
    Thunk("SHCreateShortcut", 484, forwardToArm("ceshell.dll", "SHCreateShortcut", 2));
    /* SHCreateShortcutEx(lpszShortcut, lpszTarget, lpszParams) — forward to ceshell.dll */
    Thunk("SHCreateShortcutEx", forwardToArm("ceshell.dll", "SHCreateShortcutEx", 3));
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
        LOG(THUNK, "[THUNK] ShellExecuteEx(verb='%ls', file='%ls', params='%ls', dir='%ls', nShow=%d)\n",
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
        LOG(THUNK, "[THUNK]   -> %s\n", ret ? "OK" : "FAILED");
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
        LOG(THUNK, "[THUNK] Shell_NotifyIcon(msg=%d, uID=%d, tip='%ls')\n",
               dwMessage, nid.uID, nid.szTip);
        BOOL ret = Shell_NotifyIconW(dwMessage, &nid);
        regs[0] = ret;
        return true;
    });
    /* SHGetFileInfo(pszPath, dwFileAttributes, psfi, cbFileInfo, uFlags) — forward to ceshell.dll */
    Thunk("SHGetFileInfo", 482, forwardToArm("ceshell.dll", "SHGetFileInfo", 5));
    /* GetOpenFileNameW / GetSaveFileNameW — coredll re-exports from commdlg */
    Thunk("GetOpenFileNameW", 488, forwardToArm("commdlg.dll", "GetOpenFileNameW", 1));
    Thunk("GetSaveFileNameW", 489, forwardToArm("commdlg.dll", "GetSaveFileNameW", 1));
    /* ceshell re-exports via coredll */
    /* SHGetShortcutTarget(lpszShortcut, lpszTarget, cbMax) — forward to ceshell.dll */
    Thunk("SHGetShortcutTarget", 485, forwardToArm("ceshell.dll", "SHGetShortcutTarget", 3));
    /* SHShowOutOfMemory(hwndOwner, grfFlags) — forward to ceshell.dll */
    Thunk("SHShowOutOfMemory", forwardToArm("ceshell.dll", "SHShowOutOfMemory", 2));
    Thunk("SHAddToRecentDocs", 483, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHAddToRecentDocs(uFlags=%d, pv=0x%08X) -> stub\n", regs[0], regs[1]);
        return true;
    });
    Thunk("SHGetSpecialFolderLocation", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHGetSpecialFolderLocation(...) -> E_NOTIMPL (stub)\n");
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });
    Thunk("SHGetMalloc", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHGetMalloc(...) -> E_NOTIMPL (stub)\n");
        regs[0] = 0x80004001;
        return true;
    });
    Thunk("SHGetPathFromIDList", stub0("SHGetPathFromIDList"));
    Thunk("SHBrowseForFolder", stub0("SHBrowseForFolder"));
    Thunk("SHFileOperation", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHFileOperation(...) -> ERROR (stub)\n");
        regs[0] = 1;
        return true;
    });
    Thunk("ExtractIconExW", stub0("ExtractIconExW"));
    Thunk("DragAcceptFiles", [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true; /* void */
    });
    Thunk("SHFreeNameMappings", [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true; /* void */
    });
    /* aygshell re-exports via coredll */
    Thunk("SHHandleWMSettingChange", stub0("SHHandleWMSettingChange"));
    Thunk("SHHandleWMActivate", stub0("SHHandleWMActivate"));
    ThunkOrdinal("SHInitDialog", 1791);
    ThunkOrdinal("SHFullScreen", 1790);
    Thunk("SHCreateMenuBar", stub0("SHCreateMenuBar"));
    ThunkOrdinal("SHSipPreference", 1786);
    Thunk("SHRecognizeGesture", stub0("SHRecognizeGesture"));
    Thunk("SHSendBackToFocusWindow", stub0("SHSendBackToFocusWindow"));
    ThunkOrdinal("SHSetAppKeyWndAssoc", 1784);
    ThunkOrdinal("SHDoneButton", 1782);
    Thunk("SHSipInfo", stub0("SHSipInfo"));
    ThunkOrdinal("SHNotificationAdd", 1806);
    ThunkOrdinal("SHNotificationRemove", 1808);
    ThunkOrdinal("SHNotificationUpdate", 1807);
}

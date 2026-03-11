#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* ShellExecuteEx thunk — handles CLSID paths, .lnk shortcuts, directories,
   ARM PE in-process loading, native fallback */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <shellapi.h>

void Win32Thunks::RegisterShellExecHandler() {
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
        LOG(API, "[API] ShellExecuteEx(verb='%ls', file='%ls', params='%ls', dir='%ls', nShow=%d)\n",
               verb.c_str(), file.c_str(), params.c_str(), dir.c_str(), nShow);

        /* Helper: open a folder browser via SHCreateExplorerInstance in the ARM explorer */
        auto callSHCreateExplorerInstance = [&](const std::wstring& path) -> bool {
            const uint32_t shCreateExplorerInstance = 0x0001A120;
            uint32_t path_addr = 0x60002000;
            mem.Alloc(path_addr, 0x1000);
            for (size_t j = 0; j < path.size() && j < 0x7FE; j++)
                mem.Write16(path_addr + (uint32_t)(j * 2), (uint16_t)path[j]);
            mem.Write16(path_addr + (uint32_t)(path.size() * 2), 0);
            uint32_t args[2] = { path_addr, 0 };
            LOG(API, "[API]   -> calling SHCreateExplorerInstance('%ls')\n", path.c_str());
            uint32_t ret = callback_executor(shCreateExplorerInstance, args, 2);
            LOG(API, "[API]   -> SHCreateExplorerInstance returned %d\n", ret);
            mem.Write32(sei_addr + 0x20, 42);
            regs[0] = 1;
            return true;
        };

        /* Handle CLSID shell paths (::{guid}) */
        if (file.size() > 3 && file[0] == L':' && file[1] == L':' && file[2] == L'{') {
            LOG(API, "[API]   -> CLSID shell path '%ls'\n", file.c_str());
            std::wstring folder_path;
            if (file.find(L"000214A0") != std::wstring::npos ||
                file.find(L"000214a0") != std::wstring::npos)
                folder_path = L"\\";
            else if (file.find(L"00021400") != std::wstring::npos)
                folder_path = L"\\";
            if (!folder_path.empty() && callback_executor) {
                return callSHCreateExplorerInstance(folder_path);
            }
            LOG(API, "[API]   -> unknown CLSID, returning success (stub)\n");
            mem.Write32(sei_addr + 0x20, 42);
            regs[0] = 1;
            return true;
        }

        /* Resolve WinCE .lnk shortcut files */
        if (file.size() > 4) {
            std::wstring ext = file.substr(file.size() - 4);
            for (auto& c : ext) c = towlower(c);
            if (ext == L".lnk") {
                std::wstring lnk_host = MapWinCEPath(file);
                HANDLE hf = CreateFileW(lnk_host.c_str(), GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, 0, NULL);
                if (hf != INVALID_HANDLE_VALUE) {
                    char buf[1024] = {};
                    DWORD n = 0;
                    ReadFile(hf, buf, sizeof(buf) - 1, &n, NULL);
                    CloseHandle(hf);
                    buf[n] = 0;
                    if (n > 0 && buf[0] == '#') {
                        char* p = buf + 1;
                        char* end = p;
                        while (*end && *end != '\r' && *end != '\n') end++;
                        *end = 0;
                        std::wstring target;
                        for (char* c = p; *c; c++) target += (wchar_t)*c;
                        LOG(API, "[API]   -> .lnk resolved to '%ls'\n", target.c_str());
                        file = target;
                    }
                }
            }
        }

        std::wstring mapped_file = file.empty() ? L"" : MapWinCEPath(file);
        /* WinCE resolves bare filenames via \Windows\ search path */
        if (!mapped_file.empty() && GetFileAttributesW(mapped_file.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::wstring win_path = L"\\Windows\\" + file;
            std::wstring win_mapped = MapWinCEPath(win_path);
            if (GetFileAttributesW(win_mapped.c_str()) != INVALID_FILE_ATTRIBUTES) {
                LOG(API, "[API]   -> resolved '%ls' via \\Windows\\\n", file.c_str());
                mapped_file = win_mapped;
            }
        }

        /* Directory → open folder browser */
        if (!mapped_file.empty() && callback_executor) {
            DWORD attr = GetFileAttributesW(mapped_file.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                LOG(API, "[API]   -> target is DIRECTORY\n");
                std::wstring wce_path = file;
                if (!wce_path.empty() && wce_path[0] != L'\\') wce_path = L"\\" + wce_path;
                return callSHCreateExplorerInstance(wce_path);
            }
        }

        /* ARM PE child process — launch on its own OS thread like real WinCE.
           This gives the child its own ThreadContext, ArmCpu, stack, message queue,
           and correct process name in logs. */
        if (!mapped_file.empty() && IsArmPE(mapped_file)) {
            return LaunchArmChildProcess(mapped_file, params, sei_addr, regs, mem);
        } else {
            /* Not an ARM PE — try native ShellExecuteExW */
            SHELLEXECUTEINFOW native_sei = {};
            native_sei.cbSize = sizeof(SHELLEXECUTEINFOW);
            native_sei.fMask = fMask;
            native_sei.hwnd = (HWND)(intptr_t)(int32_t)hwnd_val;
            std::wstring mapped_dir = dir.empty() ? L"" : MapWinCEPath(dir);
            native_sei.lpVerb = verb.empty() ? NULL : verb.c_str();
            native_sei.lpFile = mapped_file.empty() ? NULL : mapped_file.c_str();
            native_sei.lpParameters = params.empty() ? NULL : params.c_str();
            native_sei.lpDirectory = mapped_dir.empty() ? NULL : mapped_dir.c_str();
            native_sei.nShow = nShow;
            BOOL ret = ShellExecuteExW(&native_sei);
            mem.Write32(sei_addr + 0x20, (uint32_t)(uintptr_t)native_sei.hInstApp);
            if (fMask & SEE_MASK_NOCLOSEPROCESS)
                mem.Write32(sei_addr + 0x38, (uint32_t)(uintptr_t)native_sei.hProcess);
            LOG(API, "[API]   -> %s\n", ret ? "OK" : "FAILED");
            regs[0] = ret;
        }
        return true;
    });
}

/* Virtual Filesystem: maps WinCE paths <-> host filesystem paths.
   All WinCE paths resolve under devices/<device>/fs/ next to cerf.exe.
   Drive letters (C:\) are mapped to \c\ in WinCE space. */
#define _CRT_SECURE_NO_WARNINGS
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <fstream>
#include <algorithm>

void Win32Thunks::InitVFS(const std::string& device_override) {
    /* Determine cerf.exe directory */
    char cerf_path[MAX_PATH];
    ::GetModuleFileNameA(NULL, cerf_path, MAX_PATH);
    std::string cerf_str(cerf_path);
    size_t last_sep = cerf_str.find_last_of("\\/");
    if (last_sep != std::string::npos)
        cerf_dir = cerf_str.substr(0, last_sep + 1);
    else
        cerf_dir = "";

    /* Read cerf.ini to get device name */
    std::string ini_path = cerf_dir + "cerf.ini";
    std::ifstream ini(ini_path);
    if (ini.is_open()) {
        std::string line;
        while (std::getline(ini, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.substr(0, 7) == "device=") {
                device_name = line.substr(7);
                /* Trim whitespace */
                while (!device_name.empty() && (device_name.back() == ' ' || device_name.back() == '\t'))
                    device_name.pop_back();
            }
        }
    }
    /* CLI override takes priority */
    if (!device_override.empty()) {
        device_name = device_override;
    }
    if (device_name.empty()) {
        device_name = "wince5"; /* default */
        LOG(EMU, "[VFS] No cerf.ini found or no device= setting, defaulting to '%s'\n", device_name.c_str());
    }

    device_fs_root = cerf_dir + "devices\\" + device_name + "\\fs\\";
    device_dir = cerf_dir + "devices\\" + device_name + "\\";

    LOG(EMU, "[VFS] Device: %s\n", device_name.c_str());
    LOG(EMU, "[VFS] Device FS root: %s\n", device_fs_root.c_str());

    /* Also set wince_sys_dir for ARM DLL loading compatibility —
       it now points to the Windows subdirectory of the device fs */
    wince_sys_dir = device_fs_root + "Windows\\";
}

/* Map a WinCE path to a host filesystem path.
   Rules:
   - \Windows\foo       -> <device_fs_root>\Windows\foo
   - \My Documents\x    -> <device_fs_root>\My Documents\x
   - \anything          -> <device_fs_root>\anything
   - C:\foo\bar         -> <device_fs_root>\c\foo\bar
   - relative           -> <device_fs_root>\relative
   Empty path returns empty. */
std::wstring Win32Thunks::MapWinCEPath(const std::wstring& wce_path) {
    if (wce_path.empty()) return wce_path;

    /* Convert device_fs_root to wide string */
    std::wstring wide_fs_root;
    for (char c : device_fs_root) wide_fs_root += (wchar_t)c;

    /* Drive letter path (e.g. C:\foo\bar) -> <fs_root>\c\foo\bar */
    if (wce_path.size() >= 2 && wce_path[1] == L':') {
        wchar_t drive = wce_path[0];
        if (drive >= L'A' && drive <= L'Z') drive += 32; /* lowercase */
        std::wstring rest;
        if (wce_path.size() > 2) {
            rest = wce_path.substr(2); /* includes leading backslash */
            /* Convert leading \\ to \ */
            if (!rest.empty() && (rest[0] == L'\\' || rest[0] == L'/'))
                rest = rest.substr(1);
        }
        std::wstring result = wide_fs_root + drive + L"\\" + rest;
        LOG(THUNK, "[VFS] Map '%ls' -> '%ls'\n", wce_path.c_str(), result.c_str());
        return result;
    }

    /* Root-relative path (starts with \ or /) */
    if (wce_path[0] == L'\\' || wce_path[0] == L'/') {
        std::wstring result = wide_fs_root + wce_path.substr(1);
        LOG(THUNK, "[VFS] Map '%ls' -> '%ls'\n", wce_path.c_str(), result.c_str());
        return result;
    }

    /* Relative path — resolve under fs root */
    std::wstring result = wide_fs_root + wce_path;
    LOG(THUNK, "[VFS] Map '%ls' -> '%ls'\n", wce_path.c_str(), result.c_str());
    return result;
}

/* Reverse mapping: convert a host filesystem path back to a WinCE-style path.
   If the path is under device_fs_root, strip the prefix and add leading \.
   Otherwise return the original path unchanged. */
std::wstring Win32Thunks::MapHostToWinCE(const std::wstring& host_path) {
    if (host_path.empty()) return host_path;

    std::wstring wide_fs_root;
    for (char c : device_fs_root) wide_fs_root += (wchar_t)c;

    /* Case-insensitive prefix match */
    if (host_path.size() >= wide_fs_root.size()) {
        bool match = true;
        for (size_t i = 0; i < wide_fs_root.size(); i++) {
            wchar_t a = host_path[i], b = wide_fs_root[i];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            /* Normalize path separators */
            if (a == L'/') a = L'\\';
            if (b == L'/') b = L'\\';
            if (a != b) { match = false; break; }
        }
        if (match) {
            std::wstring relative = host_path.substr(wide_fs_root.size());
            return L"\\" + relative;
        }
    }

    /* Not under our fs root — return as-is */
    return host_path;
}

void Win32Thunks::RegisterVfsHandlers() {
    /* GetTempPathW(nBufferLength, lpBuffer) — return \Temp */
    Thunk("GetTempPathW", 162, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf_len = regs[0];
        uint32_t buf_addr = regs[1];
        const wchar_t* temp_path = L"\\Temp\\";
        size_t len = wcslen(temp_path);
        LOG(THUNK, "[THUNK] GetTempPathW(bufLen=%d) -> '%ls'\n", buf_len, temp_path);
        if (buf_addr && buf_len > len) {
            for (size_t i = 0; i <= len; i++)
                mem.Write16(buf_addr + (uint32_t)i * 2, temp_path[i]);
            /* Ensure the Temp directory exists on the host */
            std::wstring host_temp = MapWinCEPath(L"\\Temp");
            CreateDirectoryW(host_temp.c_str(), NULL);
        }
        regs[0] = (uint32_t)len;
        return true;
    });
}

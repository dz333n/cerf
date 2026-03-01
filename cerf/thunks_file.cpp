/* File I/O thunks: CreateFile, ReadFile, WriteFile, Find*, directory ops */
#include "win32_thunks.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterFileHandlers() {
    Thunk("CreateFileW", 168, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        uint32_t access = regs[1], share = regs[2];
        uint32_t creation = ReadStackArg(regs, mem, 0), flags = ReadStackArg(regs, mem, 1);
        std::wstring host_path = MapWinCEPath(wce_path);
        HANDLE h = CreateFileW(host_path.c_str(), access, share, NULL, creation, flags, NULL);
        regs[0] = WrapHandle(h);
        printf("[THUNK] CreateFileW('%ls') -> handle=0x%08X\n", wce_path.c_str(), regs[0]);
        return true;
    });
    Thunk("ReadFile", 170, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        uint32_t buf_addr = regs[1], bytes_to_read = regs[2], bytes_read_addr = regs[3];
        if (bytes_to_read > 64 * 1024 * 1024) {
            if (bytes_read_addr) mem.Write32(bytes_read_addr, 0);
            SetLastError(ERROR_INVALID_PARAMETER); regs[0] = 0; return true;
        }
        std::vector<uint8_t> buf(bytes_to_read);
        DWORD bytes_read = 0;
        BOOL ret = ReadFile(h, buf.data(), bytes_to_read, &bytes_read, NULL);
        if (ret && bytes_read > 0) {
            for (DWORD i = 0; i < bytes_read; i++) mem.Write8(buf_addr + i, buf[i]);
        }
        if (bytes_read_addr) mem.Write32(bytes_read_addr, bytes_read);
        regs[0] = ret; return true;
    });
    Thunk("WriteFile", 171, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        uint32_t buf_addr = regs[1], bytes_to_write = regs[2], bytes_written_addr = regs[3];
        if (bytes_to_write > 64 * 1024 * 1024) {
            if (bytes_written_addr) mem.Write32(bytes_written_addr, 0);
            SetLastError(ERROR_INVALID_PARAMETER); regs[0] = 0; return true;
        }
        std::vector<uint8_t> buf(bytes_to_write);
        for (uint32_t i = 0; i < bytes_to_write; i++) buf[i] = mem.Read8(buf_addr + i);
        DWORD bytes_written = 0;
        BOOL ret = WriteFile(h, buf.data(), bytes_to_write, &bytes_written, NULL);
        if (bytes_written_addr) mem.Write32(bytes_written_addr, bytes_written);
        regs[0] = ret; return true;
    });
    Thunk("GetFileSize", 172, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        DWORD high = 0;
        DWORD size = GetFileSize(h, regs[1] ? &high : NULL);
        if (regs[1]) mem.Write32(regs[1], high);
        regs[0] = size; return true;
    });
    Thunk("SetFilePointer", 173, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        LONG dist = (LONG)regs[1]; uint32_t high_addr = regs[2]; DWORD method = regs[3];
        LONG high = 0;
        if (high_addr) high = (LONG)mem.Read32(high_addr);
        DWORD result = SetFilePointer(h, dist, high_addr ? &high : NULL, method);
        if (high_addr) mem.Write32(high_addr, (uint32_t)high);
        regs[0] = result; return true;
    });
    Thunk("GetFileAttributesW", 166, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring host_path = MapWinCEPath(wce_path);
        regs[0] = GetFileAttributesW(host_path.c_str());
        return true;
    });
    Thunk("DeleteFileW", 165, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = DeleteFileW(MapWinCEPath(wce_path).c_str());
        return true;
    });
    Thunk("MoveFileW", 163, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring src = ReadWStringFromEmu(mem, regs[0]);
        std::wstring dst = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = MoveFileW(MapWinCEPath(src).c_str(), MapWinCEPath(dst).c_str());
        return true;
    });
    Thunk("CreateDirectoryW", 160, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = CreateDirectoryW(MapWinCEPath(wce_path).c_str(), NULL);
        return true;
    });
    Thunk("RemoveDirectoryW", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = RemoveDirectoryW(MapWinCEPath(wce_path).c_str());
        return true;
    });
    Thunk("FindFirstFileW", 167, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_pattern = ReadWStringFromEmu(mem, regs[0]);
        uint32_t find_data_addr = regs[1];
        std::wstring host_pattern = MapWinCEPath(wce_pattern);
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW(host_pattern.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) WriteFindDataToEmu(mem, find_data_addr, fd);
        regs[0] = WrapHandle(h);
        return true;
    });
    Thunk("FindNextFileW", 181, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        WIN32_FIND_DATAW fd = {};
        BOOL ret = FindNextFileW(h, &fd);
        if (ret) WriteFindDataToEmu(mem, regs[1], fd);
        regs[0] = ret; return true;
    });
    Thunk("FindClose", 180, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t fake = regs[0];
        HANDLE h = UnwrapHandle(fake);
        regs[0] = FindClose(h);
        RemoveHandle(fake);
        return true;
    });
    /* Ordinal-only entries */
    ThunkOrdinal("CopyFileW", 164);
    ThunkOrdinal("GetTempPathW", 162);
    ThunkOrdinal("FlushFileBuffers", 175);
    ThunkOrdinal("GetFileTime", 176);
    ThunkOrdinal("SetFileTime", 177);
    ThunkOrdinal("DeviceIoControl", 179);
    ThunkOrdinal("DeleteAndRenameFile", 183);
    ThunkOrdinal("GetDiskFreeSpaceExW", 184);
}

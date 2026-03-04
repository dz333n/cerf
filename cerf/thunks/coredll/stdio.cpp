/* Stdio thunks: _getstdfilex, fwprintf, vfwprintf, fputwc, fputws,
   fflush, _fileno, feof, ferror, fseek, ftell, fread,
   GetStdioPathW, SetStdioPathW, DeviceIoControl (console) */
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <algorithm>

void Win32Thunks::RegisterStdioHandlers() {
    /* Pre-wrap stdin/stdout/stderr so _getstdfilex returns consistent handles */
    uint32_t stdin_handle = WrapHandle((HANDLE)stdin);
    uint32_t stdout_handle = WrapHandle((HANDLE)stdout);
    uint32_t stderr_handle = WrapHandle((HANDLE)stderr);

    /* _getstdfilex(int idx) — ordinal 1100
       Returns FILE* for stdin(0), stdout(1), stderr(2) */
    Thunk("_getstdfilex", 1100, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t idx = regs[0];
        switch (idx) {
            case 0: regs[0] = stdin_handle; break;
            case 1: regs[0] = stdout_handle; break;
            case 2: regs[0] = stderr_handle; break;
            default: regs[0] = 0; break;
        }
        LOG(API, "[API] _getstdfilex(%u) -> 0x%08X\n", idx, regs[0]);
        return true;
    });

    /* Shared wide printf formatter: parse format string with args from ARM registers/stack.
       This duplicates the logic from string.cpp but is needed for fwprintf/vfwprintf. */
    auto wprintf_format = [this](EmulatedMemory& mem, const std::wstring& fmt,
                                  uint32_t* args, int nargs) -> std::wstring {
        std::wstring result;
        int arg_idx = 0;
        for (size_t i = 0; i < fmt.size(); i++) {
            if (fmt[i] == L'%' && i + 1 < fmt.size()) {
                i++;
                /* Collect flags */
                bool left_align = false, zero_pad = false, plus_flag = false;
                while (i < fmt.size() && (fmt[i] == L'-' || fmt[i] == L'+' || fmt[i] == L' ' || fmt[i] == L'0' || fmt[i] == L'#')) {
                    if (fmt[i] == L'-') left_align = true;
                    if (fmt[i] == L'0') zero_pad = true;
                    if (fmt[i] == L'+') plus_flag = true;
                    i++;
                }
                /* Collect width */
                int width = 0;
                if (i < fmt.size() && fmt[i] == L'*') {
                    if (arg_idx < nargs) width = (int)args[arg_idx++];
                    i++;
                } else {
                    while (i < fmt.size() && fmt[i] >= L'0' && fmt[i] <= L'9') {
                        width = width * 10 + (fmt[i] - L'0'); i++;
                    }
                }
                /* Precision */
                int precision = -1;
                if (i < fmt.size() && fmt[i] == L'.') {
                    i++; precision = 0;
                    if (i < fmt.size() && fmt[i] == L'*') {
                        if (arg_idx < nargs) precision = (int)args[arg_idx++];
                        i++;
                    } else {
                        while (i < fmt.size() && fmt[i] >= L'0' && fmt[i] <= L'9') {
                            precision = precision * 10 + (fmt[i] - L'0'); i++;
                        }
                    }
                }
                /* Length modifier: l, h, I64 */
                bool is_i64 = false;
                if (i + 2 < fmt.size() && fmt[i] == L'I' && fmt[i+1] == L'6' && fmt[i+2] == L'4') {
                    is_i64 = true; i += 3;
                } else if (i < fmt.size() && (fmt[i] == L'l' || fmt[i] == L'h')) {
                    i++;
                    if (i < fmt.size() && (fmt[i] == L'l' || fmt[i] == L'h')) i++;
                }
                if (i >= fmt.size()) break;
                if (arg_idx >= nargs) { result += L'?'; arg_idx++; continue; }
                wchar_t spec = fmt[i];
                /* Helper: apply width/padding to a formatted string */
                auto pad = [&](std::wstring s) {
                    while ((int)s.size() < width) {
                        if (left_align) s += L' ';
                        else s.insert(s.begin(), zero_pad ? L'0' : L' ');
                    }
                    result += s;
                };
                if (spec == L'd' || spec == L'i') {
                    wchar_t buf[32];
                    if (is_i64 && arg_idx + 1 < nargs) {
                        int64_t val = (int64_t)(((uint64_t)args[arg_idx+1] << 32) | args[arg_idx]);
                        arg_idx += 2;
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%lld", val);
                    } else {
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%d", (int)args[arg_idx++]);
                    }
                    pad(buf);
                } else if (spec == L'u') {
                    wchar_t buf[32];
                    if (is_i64 && arg_idx + 1 < nargs) {
                        uint64_t val = ((uint64_t)args[arg_idx+1] << 32) | args[arg_idx];
                        arg_idx += 2;
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%llu", val);
                    } else {
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%u", args[arg_idx++]);
                    }
                    pad(buf);
                } else if (spec == L'x') {
                    wchar_t buf[32]; _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%x", args[arg_idx++]);
                    pad(buf);
                } else if (spec == L'X') {
                    wchar_t buf[32]; _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%X", args[arg_idx++]);
                    pad(buf);
                } else if (spec == L'c') {
                    result += (wchar_t)args[arg_idx++];
                } else if (spec == L's') {
                    std::wstring s;
                    if (args[arg_idx]) s = ReadWStringFromEmu(mem, args[arg_idx]);
                    arg_idx++;
                    if (precision >= 0 && (int)s.size() > precision) s.resize(precision);
                    pad(s);
                } else if (spec == L'S') {
                    /* %S = narrow string in wide printf context */
                    std::wstring s;
                    if (args[arg_idx]) {
                        std::string ns = ReadStringFromEmu(mem, args[arg_idx]);
                        for (char c : ns) s += (wchar_t)(unsigned char)c;
                    }
                    arg_idx++;
                    if (precision >= 0 && (int)s.size() > precision) s.resize(precision);
                    pad(s);
                } else if (spec == L'p') {
                    wchar_t buf[32]; _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%08X", args[arg_idx++]);
                    result += buf;
                } else if (spec == L'%') {
                    result += L'%';
                } else { result += L'?'; arg_idx++; }
            } else result += fmt[i];
        }
        return result;
    };

    /* fwprintf(FILE*, format, ...) — ordinal 867 */
    Thunk("fwprintf", 867, [this, wprintf_format](uint32_t* regs, EmulatedMemory& mem) -> bool {
        FILE* f = (FILE*)UnwrapHandle(regs[0]);
        if (!f) { regs[0] = (uint32_t)-1; return true; }
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        uint32_t args[10];
        args[0] = regs[2]; args[1] = regs[3];
        for (int i = 2; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 2);
        std::wstring result = wprintf_format(mem, fmt, args, 10);
        int written = fwprintf(f, L"%s", result.c_str());
        regs[0] = (written >= 0) ? (uint32_t)result.size() : (uint32_t)-1;
        return true;
    });

    /* vfwprintf(FILE*, format, va_list) — ordinal 721
       In WinCE ARM, va_list is just a pointer to the args on the stack */
    Thunk("vfwprintf", 721, [this, wprintf_format](uint32_t* regs, EmulatedMemory& mem) -> bool {
        FILE* f = (FILE*)UnwrapHandle(regs[0]);
        if (!f) { regs[0] = (uint32_t)-1; return true; }
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        uint32_t va_ptr = regs[2];
        uint32_t args[10];
        for (int i = 0; i < 10; i++) args[i] = mem.Read32(va_ptr + i * 4);
        std::wstring result = wprintf_format(mem, fmt, args, 10);
        int written = fwprintf(f, L"%s", result.c_str());
        regs[0] = (written >= 0) ? (uint32_t)result.size() : (uint32_t)-1;
        return true;
    });

    /* fputwc(wint_t c, FILE*) — ordinal 1141 */
    Thunk("fputwc", 1141, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        wint_t c = (wint_t)regs[0];
        FILE* f = (FILE*)UnwrapHandle(regs[1]);
        if (!f) { regs[0] = (uint32_t)WEOF; return true; }
        regs[0] = (uint32_t)fputwc(c, f);
        return true;
    });

    /* fputws(const wchar_t*, FILE*) — ordinal 1144 */
    Thunk("fputws", 1144, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring str = ReadWStringFromEmu(mem, regs[0]);
        FILE* f = (FILE*)UnwrapHandle(regs[1]);
        if (!f) { regs[0] = (uint32_t)WEOF; return true; }
        regs[0] = (uint32_t)fputws(str.c_str(), f);
        return true;
    });

    /* fflush(FILE*) — ordinal 1122 */
    Thunk("fflush", 1122, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        if (regs[0] == 0) { fflush(NULL); regs[0] = 0; return true; }
        FILE* f = (FILE*)UnwrapHandle(regs[0]);
        regs[0] = f ? (uint32_t)fflush(f) : (uint32_t)-1;
        return true;
    });

    /* _fileno(FILE*) — ordinal 1124
       Returns the file descriptor for a FILE*. For console IOCTLs, cmd.exe
       passes this to DeviceIoControl. We return the wrapped handle directly
       since DeviceIoControl will unwrap it. */
    Thunk("_fileno", 1124, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        FILE* f = (FILE*)UnwrapHandle(regs[0]);
        if (!f) { regs[0] = (uint32_t)-1; return true; }
        regs[0] = (uint32_t)_fileno(f);
        LOG(API, "[API] _fileno(0x%08X) -> %d\n", regs[0], (int)regs[0]);
        return true;
    });

    /* feof(FILE*) — ordinal 1125 */
    Thunk("feof", 1125, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        FILE* f = (FILE*)UnwrapHandle(regs[0]);
        regs[0] = f ? (uint32_t)feof(f) : 0;
        return true;
    });

    /* ferror(FILE*) — ordinal 1126 */
    Thunk("ferror", 1126, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        FILE* f = (FILE*)UnwrapHandle(regs[0]);
        regs[0] = f ? (uint32_t)ferror(f) : 0;
        return true;
    });

    /* fseek(FILE*, long, int) — ordinal 1130 */
    Thunk("fseek", 1130, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        FILE* f = (FILE*)UnwrapHandle(regs[0]);
        if (!f) { regs[0] = (uint32_t)-1; return true; }
        regs[0] = (uint32_t)fseek(f, (long)(int32_t)regs[1], (int)regs[2]);
        return true;
    });

    /* ftell(FILE*) — ordinal 1131 */
    Thunk("ftell", 1131, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        FILE* f = (FILE*)UnwrapHandle(regs[0]);
        regs[0] = f ? (uint32_t)ftell(f) : (uint32_t)-1;
        return true;
    });

    /* fread(void*, size, count, FILE*) — ordinal 1120 */
    Thunk("fread", 1120, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf_addr = regs[0];
        uint32_t elem_size = regs[1], count = regs[2];
        FILE* f = (FILE*)UnwrapHandle(regs[3]);
        if (!f || !buf_addr) { regs[0] = 0; return true; }
        uint32_t total = elem_size * count;
        std::vector<uint8_t> buf(total);
        size_t read = fread(buf.data(), elem_size, count, f);
        uint8_t* dst = mem.Translate(buf_addr);
        if (dst) memcpy(dst, buf.data(), read * elem_size);
        regs[0] = (uint32_t)read;
        return true;
    });

    /* GetStdioPathW(int id, wchar_t* buf, DWORD* pLen) — ordinal 1149
       WinCE: returns the device path for a stdio stream.
       For console apps, return "\\CON" to indicate console is available. */
    Thunk("GetStdioPathW", 1149, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t id = regs[0], buf_addr = regs[1], len_addr = regs[2];
        LOG(API, "[API] GetStdioPathW(id=%u)\n", id);
        const wchar_t* path = L"\\CON";
        uint32_t pathlen = (uint32_t)wcslen(path);
        if (buf_addr) {
            for (uint32_t i = 0; i <= pathlen; i++)
                mem.Write16(buf_addr + i * 2, path[i]);
        }
        if (len_addr) mem.Write32(len_addr, pathlen);
        regs[0] = 1; /* TRUE */
        return true;
    });

    /* SetStdioPathW(int id, const wchar_t* path) — ordinal 1150 */
    Thunk("SetStdioPathW", 1150, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] SetStdioPathW(id=%u) -> stub\n", regs[0]);
        regs[0] = 1; return true;
    });

    /* DeviceIoControl — ordinal 179
       For console apps, handles console-specific IOCTLs:
       0x102001C = get console Y size (rows)
       0x1020024 = get console X size (columns)
       0x1020020 = set Ctrl-C handler
       0x102000C = set console title */
    Thunk("DeviceIoControl", 179, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t ioctl = regs[1];
        uint32_t inbuf = regs[2], insize = regs[3];
        uint32_t outbuf = ReadStackArg(regs, mem, 0);
        uint32_t outsize = ReadStackArg(regs, mem, 1);
        uint32_t bytes_ret = ReadStackArg(regs, mem, 2);
        LOG(API, "[API] DeviceIoControl(ioctl=0x%08X)\n", ioctl);

        /* Console IOCTLs */
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        switch (ioctl) {
            case 0x102001C: /* Get console rows */
                if (outbuf && outsize >= 4) {
                    int rows = 25;
                    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
                        rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
                    mem.Write32(outbuf, rows);
                }
                regs[0] = 1; return true;
            case 0x1020024: /* Get console columns */
                if (outbuf && outsize >= 4) {
                    int cols = 80;
                    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
                        cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
                    mem.Write32(outbuf, cols);
                }
                regs[0] = 1; return true;
            case 0x1020020: /* Set Ctrl-C handler — stub */
                LOG(API, "[API]   Console: set Ctrl-C handler (stub)\n");
                regs[0] = 1; return true;
            case 0x102000C: /* Set console title */
                if (inbuf && insize > 0) {
                    std::string title;
                    uint8_t* p = mem.Translate(inbuf);
                    if (p) title.assign((char*)p, insize);
                    SetConsoleTitleA(title.c_str());
                    LOG(API, "[API]   Console: set title '%s'\n", title.c_str());
                }
                regs[0] = 1; return true;
            default:
                LOG(API, "[API]   DeviceIoControl(0x%08X) -> stub\n", ioctl);
                regs[0] = 0; return true;
        }
    });
}

/* String and locale thunks */
#define NOMINMAX
#include "win32_thunks.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterStringHandlers() {
    Thunk("wsprintfW", 56, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst_addr = regs[0];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        uint32_t args[10];
        args[0] = regs[2]; args[1] = regs[3];
        for (int i = 2; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 2);
        std::wstring result;
        int arg_idx = 0;
        for (size_t i = 0; i < fmt.size(); i++) {
            if (fmt[i] == L'%' && i + 1 < fmt.size()) {
                i++;
                while (i < fmt.size() && (fmt[i] >= L'0' && fmt[i] <= L'9')) i++;
                if (i >= fmt.size()) break;
                if (fmt[i] == L'd' || fmt[i] == L'i') result += std::to_wstring((int)args[arg_idx++]);
                else if (fmt[i] == L'u') result += std::to_wstring(args[arg_idx++]);
                else if (fmt[i] == L'x' || fmt[i] == L'X') {
                    wchar_t buf[16]; wsprintfW(buf, L"%x", args[arg_idx++]); result += buf;
                } else if (fmt[i] == L's') result += ReadWStringFromEmu(mem, args[arg_idx++]);
                else if (fmt[i] == L'%') result += L'%';
                else { result += L'?'; arg_idx++; }
            } else result += fmt[i];
        }
        for (size_t i = 0; i < result.size(); i++) mem.Write16(dst_addr + (uint32_t)i * 2, result[i]);
        mem.Write16(dst_addr + (uint32_t)result.size() * 2, 0);
        regs[0] = (uint32_t)result.size();
        return true;
    });
    Thunk("wcslen", 63, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t len = 0;
        while (mem.Read16(regs[0] + len * 2) != 0) len++;
        regs[0] = len; return true;
    });
    Thunk("wcscpy", 61, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], i = 0; uint16_t ch;
        do { ch = mem.Read16(src + i*2); mem.Write16(dst + i*2, ch); i++; } while (ch);
        regs[0] = dst; return true;
    });
    Thunk("wcscat", 58, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], dlen = 0;
        while (mem.Read16(dst + dlen*2)) dlen++;
        uint32_t i = 0; uint16_t ch;
        do { ch = mem.Read16(src + i*2); mem.Write16(dst + (dlen+i)*2, ch); i++; } while (ch);
        regs[0] = dst; return true;
    });
    Thunk("wcscmp", 60, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)wcscmp(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str());
        return true;
    });
    Thunk("wcsncpy", 66, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], count = regs[2];
        for (uint32_t i = 0; i < count; i++) {
            uint16_t ch = mem.Read16(src + i*2); mem.Write16(dst + i*2, ch);
            if (ch == 0) { for (uint32_t j = i+1; j < count; j++) mem.Write16(dst+j*2, 0); break; }
        }
        regs[0] = dst; return true;
    });
    Thunk("wcsncmp", 65, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)wcsncmp(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str(), regs[2]);
        return true;
    });
    Thunk("_wcsicmp", 230, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)_wcsicmp(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str());
        return true;
    });
    Thunk("wcschr", 59, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t str = regs[0]; uint16_t ch = (uint16_t)regs[1];
        while (true) { uint16_t c = mem.Read16(str); if (c == ch) { regs[0] = str; return true; } if (c == 0) { regs[0] = 0; return true; } str += 2; }
    });
    Thunk("wcsrchr", 69, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t str = regs[0]; uint16_t ch = (uint16_t)regs[1]; uint32_t last = 0;
        while (true) { uint16_t c = mem.Read16(str); if (c == ch) last = str; if (c == 0) break; str += 2; }
        regs[0] = last; return true;
    });
    Thunk("wcsstr", 73, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s1 = ReadWStringFromEmu(mem, regs[0]), s2 = ReadWStringFromEmu(mem, regs[1]);
        auto pos = s1.find(s2);
        regs[0] = (pos != std::wstring::npos) ? regs[0] + (uint32_t)(pos * 2) : 0; return true;
    });
    Thunk("_wtol", 78, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)_wtol(ReadWStringFromEmu(mem, regs[0]).c_str()); return true;
    });
    Thunk("wcstol", 1082, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)wcstol(ReadWStringFromEmu(mem, regs[0]).c_str(), NULL, regs[2]); return true;
    });
    Thunk("towlower", 194, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)towlower((wint_t)regs[0]); return true; });
    Thunk("towupper", 195, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)towupper((wint_t)regs[0]); return true; });
    Thunk("iswctype", 193, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)iswctype((wint_t)regs[0], regs[1]); return true; });
    Thunk("MultiByteToWideChar", 196, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string src = ReadStringFromEmu(mem, regs[2]);
        int needed = MultiByteToWideChar(regs[0], regs[1], src.c_str(), regs[3], NULL, 0);
        if (regs[4] != 0 && regs[5] > 0) {
            std::vector<wchar_t> buf(needed + 1);
            int ret = MultiByteToWideChar(regs[0], regs[1], src.c_str(), regs[3], buf.data(), needed);
            for (int i = 0; i < ret && i < (int)regs[5]; i++) mem.Write16(regs[4] + i*2, buf[i]);
            regs[0] = ret;
        } else regs[0] = needed;
        return true;
    });
    Thunk("WideCharToMultiByte", 197, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring src = ReadWStringFromEmu(mem, regs[2]);
        int needed = WideCharToMultiByte(regs[0], regs[1], src.c_str(), regs[3], NULL, 0, NULL, NULL);
        uint32_t dst_addr = ReadStackArg(regs, mem, 0), dst_size = ReadStackArg(regs, mem, 1);
        if (dst_addr && dst_size > 0) {
            std::vector<char> buf(needed + 1);
            int ret = WideCharToMultiByte(regs[0], regs[1], src.c_str(), regs[3], buf.data(), needed, NULL, NULL);
            for (int i = 0; i < ret && i < (int)dst_size; i++) mem.Write8(dst_addr + i, buf[i]);
            regs[0] = ret;
        } else regs[0] = needed;
        return true;
    });
    Thunk("FormatMessageW", 234, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("CompareStringW", 198, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = CSTR_EQUAL; return true; });
    Thunk("GetStringTypeW", 216, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("CharLowerW", 221, [](uint32_t* regs, EmulatedMemory&) -> bool {
        if ((regs[0] & 0xFFFF0000) == 0) regs[0] = (uint32_t)towlower(regs[0]); return true;
    });
    Thunk("CharUpperW", 224, [](uint32_t* regs, EmulatedMemory&) -> bool {
        if ((regs[0] & 0xFFFF0000) == 0) regs[0] = (uint32_t)towupper(regs[0]); return true;
    });
    Thunk("CharNextW", 226, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[0] && mem.Read16(regs[0]) != 0) regs[0] += 2; return true;
    });
    Thunk("lstrcmpW", 227, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)lstrcmpW(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str()); return true;
    });
    Thunk("lstrcmpiW", 228, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)lstrcmpiW(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str()); return true;
    });
    Thunk("_wcsnicmp", 229, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)_wcsnicmp(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str(), regs[2]); return true;
    });
    Thunk("_wcsdup", 74, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        static uint32_t next_dup = 0x43000000;
        uint32_t sz = ((uint32_t)s.size() + 1) * 2;
        mem.Alloc(next_dup, sz);
        for (size_t i = 0; i <= s.size(); i++) mem.Write16(next_dup + (uint32_t)i*2, s[i]);
        regs[0] = next_dup; next_dup += (sz + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("wcstombs", 75, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring src = ReadWStringFromEmu(mem, regs[1]);
        uint32_t dst = regs[0], count = regs[2];
        for (uint32_t i = 0; i < count && i < (uint32_t)src.size(); i++) mem.Write8(dst+i, (uint8_t)src[i]);
        if (count > 0) mem.Write8(dst + std::min(count-1, (uint32_t)src.size()), 0);
        regs[0] = (uint32_t)src.size(); return true;
    });
    Thunk("mbstowcs", 76, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string src = ReadStringFromEmu(mem, regs[1]);
        uint32_t dst = regs[0], count = regs[2];
        for (uint32_t i = 0; i < count && i < (uint32_t)src.size(); i++) mem.Write16(dst+i*2, (uint16_t)(uint8_t)src[i]);
        if (count > 0) mem.Write16(dst + std::min(count-1, (uint32_t)src.size())*2, 0);
        regs[0] = (uint32_t)src.size(); return true;
    });
    Thunk("wcstok", 77, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    thunk_handlers["wcspbrk"] = thunk_handlers["wcstok"];
    Thunk("_snwprintf", 1096, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    thunk_handlers["swprintf"] = thunk_handlers["_snwprintf"];
    thunk_handlers["swscanf"] = thunk_handlers["_snwprintf"];
    thunk_handlers["wvsprintfW"] = thunk_handlers["_snwprintf"];
    Thunk("sprintf", 1058, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });

    /* Ordinal-only entries (name mapping, no handler) */
    ThunkOrdinal("wvsprintfW", 57);
    ThunkOrdinal("wcsncat", 64);
    ThunkOrdinal("wcspbrk", 68);
    ThunkOrdinal("swprintf", 1097);
    ThunkOrdinal("swscanf", 1098);
}

#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Misc small stubs: debug, clipboard, caret, sound, RAS, COM, IMM, gestures, C runtime */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <objbase.h>

void Win32Thunks::RegisterMiscHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(THUNK, "[THUNK] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    auto stub1 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(THUNK, "[THUNK] [STUB] %s -> 1\n", name); regs[0] = 1; return true;
        };
    };
    /* Debug */
    Thunk("OutputDebugStringW", 541, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(DBG, "[DEBUG] %ls\n", ReadWStringFromEmu(mem, regs[0]).c_str()); return true;
    });
    Thunk("NKDbgPrintfW", 545, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(DBG, "[NKDbg] %ls\n", ReadWStringFromEmu(mem, regs[0]).c_str()); return true;
    });
    /* Clipboard */
    Thunk("OpenClipboard", 668, stub1("OpenClipboard"));
    Thunk("CloseClipboard", 669, stub1("CloseClipboard"));
    Thunk("EmptyClipboard", 677, stub1("EmptyClipboard"));
    Thunk("GetClipboardData", 672, stub0("GetClipboardData"));
    Thunk("SetClipboardData", 671, stub0("SetClipboardData"));
    Thunk("IsClipboardFormatAvailable", 678, stub0("IsClipboardFormatAvailable"));
    Thunk("EnumClipboardFormats", 675, stub0("EnumClipboardFormats"));
    /* Caret */
    Thunk("CreateCaret", 658, stub1("CreateCaret"));
    Thunk("HideCaret", 660, stub1("HideCaret"));
    Thunk("ShowCaret", 661, stub1("ShowCaret"));
    /* Sound */
    Thunk("sndPlaySoundW", 377, stub1("sndPlaySoundW"));
    Thunk("waveOutSetVolume", 382, stub0("waveOutSetVolume"));
    /* RAS */
    Thunk("RasDial", 342, stub0("RasDial"));
    Thunk("RasHangup", stub0("RasHangup"));
    thunk_handlers["RasHangUp"] = thunk_handlers["RasHangup"];
    /* C runtime misc */
    Thunk("_purecall", 1092, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] _purecall\n"); regs[0] = 0; return true;
    });
    Thunk("terminate", 1556, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] terminate\n"); ExitProcess(3); return true;
    });
    Thunk("__security_gen_cookie", 1875, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0xBB40E64E; return true; });
    Thunk("__security_gen_cookie2", 2696, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0xBB40E64E; return true; });
    Thunk("CeGenRandom", 1601, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (uint32_t i = 0; i < regs[0]; i++) mem.Write8(regs[1] + i, (uint8_t)(rand() & 0xFF));
        regs[0] = 1; return true;
    });
    Thunk("MulDiv", 1877, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = MulDiv((int)regs[0], (int)regs[1], (int)regs[2]); return true;
    });
    Thunk("_except_handler4_common", 87, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("setjmp", 2054, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("_setjmp3", [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* Misc kernel stubs */
    Thunk("FlushInstructionCache", 508, stub1("FlushInstructionCache"));
    Thunk("GetProcessIndexFromID", stub1("GetProcessIndexFromID"));
    Thunk("EventModify", 494, stub1("EventModify"));
    Thunk("GlobalAddAtomW", 1519, stub1("GlobalAddAtomW"));
    Thunk("GetAPIAddress", 32, stub0("GetAPIAddress"));
    Thunk("WaitForAPIReady", 2562, stub0("WaitForAPIReady"));
    Thunk("__GetUserKData", 2528, stub0("__GetUserKData"));
    /* Gesture stubs */
    Thunk("RegisterDefaultGestureHandler", 2928, stub0("RegisterDefaultGestureHandler"));
    Thunk("GetGestureInfo", 2925, stub0("GetGestureInfo"));
    Thunk("GetGestureExtraArguments", stub0("GetGestureExtraArguments"));
    Thunk("CloseGestureInfoHandle", 2924, stub0("CloseGestureInfoHandle"));
    /* COM — WinCE coredll re-exports COM functions from ole32. Both DLLs resolve
       to the same handler here since our dispatch is name-based (flat map). */
    Thunk("CoInitializeEx", [](uint32_t* regs, EmulatedMemory&) -> bool {
        HRESULT hr = CoInitializeEx(NULL, regs[1]);
        LOG(THUNK, "[THUNK] CoInitializeEx(0x%X) -> 0x%08X\n", regs[1], (uint32_t)hr);
        regs[0] = (uint32_t)hr;
        return true;
    });
    Thunk("CoUninitialize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] CoUninitialize()\n");
        CoUninitialize(); regs[0] = 0; return true;
    });
    /* IMM stubs */
    Thunk("ImmAssociateContext", 770, stub0("ImmAssociateContext"));
    Thunk("ImmGetContext", 783, stub0("ImmGetContext"));
    Thunk("ImmReleaseContext", 803, stub0("ImmReleaseContext"));
    Thunk("ImmGetOpenStatus", 792, stub0("ImmGetOpenStatus"));
    Thunk("ImmNotifyIME", 800, stub0("ImmNotifyIME"));
    Thunk("ImmSetOpenStatus", 814, stub0("ImmSetOpenStatus"));
    /* Clipboard */
    Thunk("RegisterClipboardFormatW", 673, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring fmt = ReadWStringFromEmu(mem, regs[0]);
        LOG(THUNK, "[THUNK] RegisterClipboardFormatW('%ls')\n", fmt.c_str());
        UINT id = RegisterClipboardFormatW(fmt.c_str());
        regs[0] = id;
        return true;
    });
    Thunk("GetClipboardOwner", 670, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] GetClipboardOwner() -> NULL (stub)\n");
        regs[0] = 0;
        return true;
    });
    /* Monitor */
    Thunk("MonitorFromWindow", 1524, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] MonitorFromWindow(hwnd=0x%08X, flags=0x%X) -> stub\n", regs[0], regs[1]);
        regs[0] = 1; /* fake monitor handle */
        return true;
    });
    Thunk("GetMonitorInfo", 1525, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(THUNK, "[THUNK] GetMonitorInfo(hMonitor=0x%08X, lpmi=0x%08X) -> stub\n", regs[0], regs[1]);
        if (regs[1]) {
            /* Fill MONITORINFO with desktop work area */
            RECT wa;
            SystemParametersInfo(SPI_GETWORKAREA, 0, &wa, 0);
            uint32_t addr = regs[1];
            /* cbSize already set by caller; rcMonitor */
            mem.Write32(addr + 4, 0); mem.Write32(addr + 8, 0);
            mem.Write32(addr + 12, wa.right); mem.Write32(addr + 16, wa.bottom);
            /* rcWork */
            mem.Write32(addr + 20, wa.left); mem.Write32(addr + 24, wa.top);
            mem.Write32(addr + 28, wa.right); mem.Write32(addr + 32, wa.bottom);
            /* dwFlags = MONITORINFOF_PRIMARY */
            mem.Write32(addr + 36, 1);
        }
        regs[0] = 1;
        return true;
    });
    /* Additional IMM stubs needed by RICHED20.DLL */
    Thunk("ImmEscapeW", 775, stub0("ImmEscapeW"));
    Thunk("ImmGetCandidateWindow", 779, stub0("ImmGetCandidateWindow"));
    Thunk("ImmGetCompositionStringW", 781, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] ImmGetCompositionStringW(himc=0x%08X, dwIndex=0x%X) -> 0 (stub)\n", regs[0], regs[1]);
        regs[0] = 0; return true;
    });
    Thunk("ImmGetConversionStatus", 785, stub0("ImmGetConversionStatus"));
    Thunk("ImmGetProperty", 793, stub0("ImmGetProperty"));
    Thunk("ImmSetCandidateWindow", 807, stub0("ImmSetCandidateWindow"));
    Thunk("ImmSetCompositionFontW", 808, stub0("ImmSetCompositionFontW"));
    Thunk("ImmSetCompositionStringW", 809, stub0("ImmSetCompositionStringW"));
    Thunk("ImmSetCompositionWindow", 810, stub0("ImmSetCompositionWindow"));
    Thunk("ImmGetVirtualKey", 1210, stub0("ImmGetVirtualKey"));
    Thunk("PostKeybdMessage", 832, stub0("PostKeybdMessage"));
    /* Memory validation */
    Thunk("IsBadReadPtr", 522, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; /* Always return FALSE - pointer is valid */
        return true;
    });
    Thunk("IsBadWritePtr", 523, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });
    /* Keyboard */
    Thunk("GetKeyboardLayout", 1229, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x04090409; /* US English */
        return true;
    });
    /* Ordinal-only entries */
    ThunkOrdinal("GetOwnerProcess", 606);
    ThunkOrdinal("Random", 80);
}

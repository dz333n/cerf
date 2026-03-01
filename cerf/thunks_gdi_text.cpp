/* GDI thunks: fonts, text metrics, DrawTextW, ExtTextOutW */
#include "win32_thunks.h"
#include <cstdio>

void Win32Thunks::RegisterGdiTextHandlers() {
    Thunk("CreateFontIndirectW", 895, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOGFONTW lf = {};
        lf.lfHeight = (LONG)mem.Read32(regs[0]); lf.lfWidth = (LONG)mem.Read32(regs[0]+4);
        lf.lfWeight = (LONG)mem.Read32(regs[0]+16); lf.lfCharSet = mem.Read8(regs[0]+23);
        for (int i = 0; i < 32; i++) { lf.lfFaceName[i] = mem.Read16(regs[0]+28+i*2); if (!lf.lfFaceName[i]) break; }
        regs[0] = (uint32_t)(uintptr_t)CreateFontIndirectW(&lf); return true;
    });
    Thunk("GetTextMetricsW", 898, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        TEXTMETRICW tm; BOOL ret = GetTextMetricsW((HDC)(intptr_t)(int32_t)regs[0], &tm);
        if (ret && regs[1]) {
            mem.Write32(regs[1]+0, tm.tmHeight); mem.Write32(regs[1]+4, tm.tmAscent);
            mem.Write32(regs[1]+8, tm.tmDescent); mem.Write32(regs[1]+12, tm.tmInternalLeading);
            mem.Write32(regs[1]+16, tm.tmExternalLeading); mem.Write32(regs[1]+20, tm.tmAveCharWidth);
            mem.Write32(regs[1]+24, tm.tmMaxCharWidth); mem.Write32(regs[1]+28, tm.tmWeight);
            mem.Write32(regs[1]+32, tm.tmOverhang); mem.Write32(regs[1]+36, tm.tmDigitizedAspectX);
            mem.Write32(regs[1]+40, tm.tmDigitizedAspectY);
            mem.Write16(regs[1]+44, tm.tmFirstChar); mem.Write16(regs[1]+46, tm.tmLastChar);
            mem.Write16(regs[1]+48, tm.tmDefaultChar); mem.Write16(regs[1]+50, tm.tmBreakChar);
            mem.Write8(regs[1]+52, tm.tmItalic); mem.Write8(regs[1]+53, tm.tmUnderlined);
            mem.Write8(regs[1]+54, tm.tmStruckOut); mem.Write8(regs[1]+55, tm.tmPitchAndFamily);
            mem.Write8(regs[1]+56, tm.tmCharSet);
        }
        regs[0] = ret; return true;
    });
    Thunk("DrawTextW", 945, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        std::wstring text = ReadWStringFromEmu(mem, regs[1]);
        int count = (int32_t)regs[2]; uint32_t rect_addr = regs[3];
        uint32_t format = ReadStackArg(regs, mem, 0);
        RECT rc; rc.left = (int32_t)mem.Read32(rect_addr); rc.top = (int32_t)mem.Read32(rect_addr+4);
        rc.right = (int32_t)mem.Read32(rect_addr+8); rc.bottom = (int32_t)mem.Read32(rect_addr+12);
        int ret = ::DrawTextW(hdc, text.c_str(), count, &rc, format);
        mem.Write32(rect_addr, (uint32_t)rc.left); mem.Write32(rect_addr+4, (uint32_t)rc.top);
        mem.Write32(rect_addr+8, (uint32_t)rc.right); mem.Write32(rect_addr+12, (uint32_t)rc.bottom);
        regs[0] = (uint32_t)ret; return true;
    });
    Thunk("SetTextAlign", 1654, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetTextAlign((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("GetTextAlign", 1655, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetTextAlign((HDC)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("ExtTextOutW", 896, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("GetTextExtentExPointW", 897, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
}

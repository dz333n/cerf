/* Dialog thunks: CreateDialog, DialogBox, EndDialog, DlgItem functions */
#define NOMINMAX
#include "win32_thunks.h"
#include <cstdio>
#include <vector>

/* Helper: compute size of a DLGTEMPLATE (with all items) in emulated memory. */
static uint32_t ComputeDlgTemplateSize(EmulatedMemory& mem, uint32_t addr) {
    uint32_t p = addr;
    uint16_t cdit = mem.Read16(p + 8);
    p += 18;
    uint16_t w = mem.Read16(p);
    if (w == 0x0000) { p += 2; }
    else if (w == 0xFFFF) { p += 4; }
    else { while (mem.Read16(p)) p += 2; p += 2; }
    w = mem.Read16(p);
    if (w == 0x0000) { p += 2; }
    else if (w == 0xFFFF) { p += 4; }
    else { while (mem.Read16(p)) p += 2; p += 2; }
    while (mem.Read16(p)) p += 2; p += 2;
    uint32_t style = mem.Read32(addr);
    if (style & DS_SETFONT) { p += 2; while (mem.Read16(p)) p += 2; p += 2; }
    for (int i = 0; i < cdit; i++) {
        p = (p + 3) & ~3u;
        p += 18;
        w = mem.Read16(p);
        if (w == 0xFFFF) { p += 4; }
        else { while (mem.Read16(p)) p += 2; p += 2; }
        w = mem.Read16(p);
        if (w == 0xFFFF) { p += 4; }
        else { while (mem.Read16(p)) p += 2; p += 2; }
        uint16_t extra = mem.Read16(p);
        p += 2 + extra;
    }
    return p - addr;
}

static std::vector<uint8_t> CopyDlgTemplate(EmulatedMemory& mem, uint32_t addr) {
    uint32_t size = ComputeDlgTemplateSize(mem, addr);
    std::vector<uint8_t> buf(size);
    for (uint32_t i = 0; i < size; i++) buf[i] = mem.Read8(addr + i);
    return buf;
}

void Win32Thunks::RegisterDialogHandlers() {
    Thunk("CreateDialogIndirectParamW", 688, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t lpTemplate = regs[1], hwndParent = regs[2], arm_dlgProc = regs[3];
        LPARAM initParam = (LPARAM)ReadStackArg(regs, mem, 0);
        auto tmpl = CopyDlgTemplate(mem, lpTemplate);
        HWND dlg = CreateDialogIndirectParamW(GetModuleHandleW(NULL),
            (LPCDLGTEMPLATEW)tmpl.data(), (HWND)(intptr_t)(int32_t)hwndParent, EmuDlgProc, initParam);
        if (dlg && arm_dlgProc) hwnd_dlgproc_map[dlg] = arm_dlgProc;
        regs[0] = (uint32_t)(uintptr_t)dlg;
        return true;
    });
    Thunk("DialogBoxIndirectParamW", 690, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t lpTemplate = regs[1], hwndParent = regs[2], arm_dlgProc = regs[3];
        LPARAM initParam = (LPARAM)ReadStackArg(regs, mem, 0);
        HWND parent = (HWND)(intptr_t)(int32_t)hwndParent;
        auto tmpl = CopyDlgTemplate(mem, lpTemplate);
        modal_dlg_ended = false;
        modal_dlg_result = 0;
        HWND dlg = CreateDialogIndirectParamW(GetModuleHandleW(NULL),
            (LPCDLGTEMPLATEW)tmpl.data(), parent, EmuDlgProc, initParam);
        if (dlg && arm_dlgProc) {
            hwnd_dlgproc_map[dlg] = arm_dlgProc;
            uint32_t args[4] = { (uint32_t)(uintptr_t)dlg, WM_INITDIALOG, 0, (uint32_t)initParam };
            callback_executor(arm_dlgProc, args, 4);
        }
        if (dlg) {
            ShowWindow(dlg, SW_SHOW);
            if (parent) EnableWindow(parent, FALSE);
            MSG msg;
            while (!modal_dlg_ended && GetMessageW(&msg, NULL, 0, 0)) {
                if (!IsDialogMessageW(dlg, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
            }
            if (parent) EnableWindow(parent, TRUE);
            DestroyWindow(dlg);
            hwnd_dlgproc_map.erase(dlg);
            if (parent) SetForegroundWindow(parent);
        }
        regs[0] = (uint32_t)modal_dlg_result;
        return true;
    });
    Thunk("EndDialog", 691, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND dlg = (HWND)(intptr_t)(int32_t)regs[0];
        modal_dlg_result = (INT_PTR)(int32_t)regs[1];
        modal_dlg_ended = true;
        ShowWindow(dlg, SW_HIDE);
        regs[0] = 1;
        return true;
    });
    Thunk("GetDlgItem", 692, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetDlgItem((HWND)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    });
    Thunk("SetDlgItemTextW", 686, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring text = ReadWStringFromEmu(mem, regs[2]);
        regs[0] = SetDlgItemTextW((HWND)(intptr_t)(int32_t)regs[0], regs[1], text.c_str());
        return true;
    });
    Thunk("GetDlgItemTextW", 687, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        wchar_t buf[1024] = {}; uint32_t maxlen = regs[3]; if (maxlen > 1024) maxlen = 1024;
        int ret = GetDlgItemTextW((HWND)(intptr_t)(int32_t)regs[0], regs[1], buf, maxlen);
        for (int i = 0; i <= ret; i++) mem.Write16(regs[2] + i * 2, buf[i]);
        regs[0] = ret;
        return true;
    });
    Thunk("SendDlgItemMessageW", 685, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)SendDlgItemMessageW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0));
        return true;
    });
    Thunk("CheckRadioButton", 684, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = CheckRadioButton((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    });
    Thunk("DefDlgProcW", 689, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)DefDlgProcW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    });
    Thunk("GetDlgCtrlID", 693, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetDlgCtrlID((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    });
    Thunk("GetNextDlgTabItem", 696, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetNextDlgTabItem(
            (HWND)(intptr_t)(int32_t)regs[0], (HWND)(intptr_t)(int32_t)regs[1], regs[2]);
        return true;
    });
    Thunk("IsDialogMessageW", 698, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });
}

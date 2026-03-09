#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <commctrl.h>
#include <dwmapi.h>
#pragma comment(lib, "comctl32")
#pragma comment(lib, "dwmapi")

/* Static member definitions for callback infrastructure */
std::map<HWND, uint32_t> Win32Thunks::hwnd_wndproc_map;
std::map<UINT_PTR, uint32_t> Win32Thunks::arm_timer_callbacks;
std::map<HWND, uint32_t> Win32Thunks::hwnd_dlgproc_map;
uint32_t Win32Thunks::pending_arm_dlgproc = 0;
uint16_t Win32Thunks::pending_template_cx = 0;
uint16_t Win32Thunks::pending_template_cy = 0;
HWND Win32Thunks::dlu_override_hwnd = nullptr;
int Win32Thunks::dlu_override_client_w = 0;
int Win32Thunks::dlu_override_client_h = 0;
INT_PTR Win32Thunks::modal_dlg_result = 0;
bool Win32Thunks::modal_dlg_ended = false;
Win32Thunks* Win32Thunks::s_instance = nullptr;
std::set<HWND> Win32Thunks::captionok_hwnds;

LRESULT CALLBACK Win32Thunks::EmuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!s_instance || !s_instance->callback_executor) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    auto it = hwnd_wndproc_map.find(hwnd);
    if (it == hwnd_wndproc_map.end()) {
        /* During CreateWindow, HWND is not yet in the map.
           Look up the ARM WndProc from the window class name and auto-register. */
        wchar_t cls_name[256] = {};
        GetClassNameW(hwnd, cls_name, 256);
        auto cls_it = s_instance->arm_wndprocs.find(cls_name);
        if (cls_it != s_instance->arm_wndprocs.end()) {
            hwnd_wndproc_map[hwnd] = cls_it->second;
            it = hwnd_wndproc_map.find(hwnd);
        } else {
            if (msg == WM_CREATE || msg == WM_NCCREATE) {
                LOG(API, "[API] EmuWndProc: MISS class='%ls' msg=0x%04X hwnd=0x%p -> DefWindowProc\n",
                    cls_name, msg, hwnd);
            }
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    }

    /* One-time deferred arrange fix for SysListView32.
       ARM commctrl defers item positioning via PostMessage(WM_USER), but those
       messages get dispatched by the pseudo-thread message loop while the window
       is still at its initial small size. On the first WM_PAINT with items present
       (window is at final size, all items inserted/sorted), force LVM_ARRANGE
       to recompute positions using the correct dimensions. */
    if (msg == WM_PAINT && !GetPropW(hwnd, L"CerfLVArr")) {
        wchar_t cls_chk[64] = {};
        GetClassNameW(hwnd, cls_chk, 64);
        if (wcsstr(cls_chk, L"SysListView32")) {
            int count = (int)::SendMessageW(hwnd, 0x1004 /* LVM_GETITEMCOUNT */, 0, 0);
            if (count > 0) {
                SetPropW(hwnd, L"CerfLVArr", (HANDLE)1);
                LOG(API, "[API] SysListView32 first WM_PAINT: %d items, sending LVM_ARRANGE\n", count);
                ::SendMessageW(hwnd, 0x1016 /* LVM_ARRANGE */, 0, 0);
            }
        }
    }

    /* Messages with native pointer lParams need marshaling.
       For messages we can't marshal, use DefWindowProcW. */
    LPARAM native_lParam = lParam; /* Save for writeback after ARM callback */
    switch (msg) {
    /* Messages with native 64-bit pointers in wParam/lParam that would be
       corrupted if truncated to 32-bit for the ARM WndProc. Route these
       directly to DefWindowProcW to avoid pointer truncation. */
    case WM_GETMINMAXINFO:      /* lParam = MINMAXINFO* */
    case WM_NCCALCSIZE:         /* lParam = NCCALCSIZE_PARAMS* */
    case WM_NCDESTROY:
    case WM_SETICON:            /* lParam = HICON (64-bit on x64) */
    case WM_GETICON:
    case WM_COPYDATA:           /* lParam = COPYDATASTRUCT* */
    case WM_DEVICECHANGE:
    case WM_POWERBROADCAST:
    case WM_INPUT:              /* lParam = HRAWINPUT */
    case WM_NCPAINT:
    /* Undocumented User32 Aero Handler (UAH) theme messages (0x90-0x95).
       Sent internally by TrackPopupMenuEx and other menu APIs on Windows 10/11.
       These carry native 64-bit pointers that would crash if truncated to 32-bit
       for ARM code. WinCE apps don't know about these. */
    case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
    /* Menu-loop messages sent to the owner window by TrackPopupMenuEx.
       WM_ENTERMENULOOP/WM_EXITMENULOOP are desktop-only and WinCE apps
       don't expect them. WM_MENUSELECT lParam = HMENU (64-bit handle). */
    case WM_ENTERMENULOOP:  /* 0x0211 */
    case WM_EXITMENULOOP:   /* 0x0212 */
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    case WM_NOTIFY: {
        /* WM_NOTIFY from ARM commctrl: lParam is a pointer to NMHDR in ARM memory.
           Check if it's an ARM pointer (fits in 32 bits) and forward to ARM WndProc.
           Native WM_NOTIFY (from real Win32 controls like SysListView32) has a
           64-bit lParam pointing to native NMHDR. Marshal it to ARM memory. */
        if (lParam > 0 && (lParam >> 32) == 0) {
            /* ARM pointer — peek at LVN_GETDISPINFO before/after for debugging */
            EmulatedMemory& emem = s_instance->mem;
            uint32_t arm_lp = (uint32_t)lParam;
            int32_t code_peek = (int32_t)emem.Read32(arm_lp + 8);
            if (code_peek == LVN_GETDISPINFOW || code_peek == LVN_GETDISPINFOA) {
                /* ARM LVITEMW at arm_lp+12: mask(+0) iItem(+4) iSubItem(+8) state(+12)
                   stateMask(+16) pszText(+20) cchTextMax(+24) iImage(+28) lParam(+32) */
                uint32_t mask = emem.Read32(arm_lp + 12);
                int iItem = (int)emem.Read32(arm_lp + 16);
                int iImage = (int)emem.Read32(arm_lp + 40);
                uint32_t pszText = emem.Read32(arm_lp + 32);
                LOG(API, "[DISP] LVN_GETDISPINFO(ARM) BEFORE: iItem=%d mask=0x%X iImage=%d pszText=0x%08X\n",
                    iItem, mask, iImage, pszText);
                /* Forward to ARM WndProc */
                uint32_t arm_wndproc = it->second;
                uint32_t args[4] = {
                    (uint32_t)(uintptr_t)hwnd, WM_NOTIFY,
                    (uint32_t)wParam, arm_lp
                };
                uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);
                /* Read back results */
                iImage = (int)emem.Read32(arm_lp + 40);
                pszText = emem.Read32(arm_lp + 32);
                std::wstring disp_text;
                if (pszText && (mask & 0x0001 /*LVIF_TEXT*/)) {
                    for (int i = 0; i < 64; i++) {
                        wchar_t c = (wchar_t)emem.Read16(pszText + i * 2);
                        if (!c) break;
                        disp_text += c;
                    }
                }
                LOG(API, "[DISP] LVN_GETDISPINFO(ARM) AFTER: iItem=%d iImage=%d text='%ls'\n",
                    iItem, iImage, disp_text.c_str());
                return (LRESULT)(intptr_t)(int32_t)result;
            }
            break; /* Already an ARM pointer — forward directly */
        }
        if (!lParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        /* Native NMHDR at lParam. Marshal to ARM emulated memory. */
        NMHDR* pnm = (NMHDR*)lParam;
        EmulatedMemory& emem = s_instance->mem;
        static uint32_t nm_emu_base = 0x3F003000;
        if (!emem.IsValid(nm_emu_base)) emem.Alloc(nm_emu_base, 0x1000);
        int code = pnm->code;
        /* LVN_GETDISPINFOW = LVN_FIRST - 77 = -177, LVN_GETDISPINFOA = -150
           Marshal NMLVDISPINFOW: NMHDR(12) + LVITEMW(36 on ARM) = 48 bytes */
        if (code == LVN_GETDISPINFOW || code == LVN_GETDISPINFOA) {
            NMLVDISPINFOW* pdi = (NMLVDISPINFOW*)lParam;
            uint32_t a = nm_emu_base;
            /* NMHDR: hwndFrom(4), idFrom(4), code(4) */
            emem.Write32(a + 0, (uint32_t)(uintptr_t)pdi->hdr.hwndFrom);
            emem.Write32(a + 4, (uint32_t)pdi->hdr.idFrom);
            emem.Write32(a + 8, (uint32_t)pdi->hdr.code);
            /* ARM LVITEMW at offset 12: mask(4) iItem(4) iSubItem(4) state(4) stateMask(4) pszText(4) cchTextMax(4) iImage(4) lParam(4) */
            emem.Write32(a + 12, pdi->item.mask);
            emem.Write32(a + 16, pdi->item.iItem);
            emem.Write32(a + 20, pdi->item.iSubItem);
            emem.Write32(a + 24, pdi->item.state);
            emem.Write32(a + 28, pdi->item.stateMask);
            /* Allocate text buffer in emu memory for ARM to fill */
            uint32_t text_buf_emu = nm_emu_base + 0x100;
            int text_max = pdi->item.cchTextMax > 0 ? pdi->item.cchTextMax : 260;
            if (text_max > 400) text_max = 400;
            emem.Write32(a + 32, text_buf_emu); /* pszText */
            emem.Write32(a + 36, text_max);     /* cchTextMax */
            emem.Write32(a + 40, pdi->item.iImage);
            emem.Write32(a + 44, (uint32_t)(int32_t)pdi->item.lParam);
            emem.Write16(text_buf_emu, 0); /* clear text buffer */
            /* Call ARM WndProc with marshaled data */
            uint32_t arm_wndproc = it->second;
            uint32_t args[4] = {
                (uint32_t)(uintptr_t)hwnd, WM_NOTIFY,
                (uint32_t)wParam, a
            };
            uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);
            /* Copy results back to native struct */
            pdi->item.state = emem.Read32(a + 24);
            pdi->item.iImage = (int)emem.Read32(a + 40);
            pdi->item.lParam = (LPARAM)(int32_t)emem.Read32(a + 44);
            /* Read back text if ARM code filled it in */
            if (pdi->item.mask & LVIF_TEXT) {
                uint32_t arm_text_ptr = emem.Read32(a + 32);
                if (arm_text_ptr && pdi->item.pszText && pdi->item.cchTextMax > 0) {
                    int i;
                    for (i = 0; i < pdi->item.cchTextMax - 1; i++) {
                        wchar_t c = (wchar_t)emem.Read16(arm_text_ptr + i * 2);
                        pdi->item.pszText[i] = c;
                        if (!c) break;
                    }
                    pdi->item.pszText[i] = 0;
                }
            }
            return (LRESULT)(intptr_t)(int32_t)result;
        }
        /* For other native WM_NOTIFY codes, marshal basic NMHDR to ARM */
        {
            uint32_t a = nm_emu_base;
            emem.Write32(a + 0, (uint32_t)(uintptr_t)pnm->hwndFrom);
            emem.Write32(a + 4, (uint32_t)pnm->idFrom);
            emem.Write32(a + 8, (uint32_t)pnm->code);
            /* Copy extra data after NMHDR (up to 128 bytes) for notifications
               that carry additional fields (NM_CUSTOMDRAW, etc.) */
            uint8_t* src = (uint8_t*)pnm + 12;
            for (int i = 0; i < 128; i++)
                emem.Write8(a + 12 + i, src[i]);
            uint32_t arm_wndproc = it->second;
            uint32_t args[4] = {
                (uint32_t)(uintptr_t)hwnd, WM_NOTIFY,
                (uint32_t)wParam, a
            };
            uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);
            return (LRESULT)(intptr_t)(int32_t)result;
        }
    }
    case WM_NCHITTEST:
        /* lParam = MAKELPARAM(x, y) — no pointers, safe to forward to ARM WndProc.
           Needed for commctrl hit-testing (toolbar buttons, rebar bands, etc.) */
        break;
    case WM_DISPLAYCHANGE:
        break; /* wParam=bpp, lParam=MAKELPARAM(cx,cy) — no pointers */
    case WM_DELETEITEM: {
        /* lParam = DELETEITEMSTRUCT* — ARM commctrl sends this with ARM pointers */
        if (lParam > 0 && (lParam >> 32) == 0) {
            break;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    case WM_COMPAREITEM: {
        if (lParam > 0 && (lParam >> 32) == 0) {
            break;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    case WM_WINDOWPOSCHANGING:
    case WM_WINDOWPOSCHANGED: {
        /* Marshal WINDOWPOS (x64: 36 bytes with 8-byte handles → ARM: 28 bytes with 4-byte handles).
           ARM layout: hwnd(4) hwndInsertAfter(4) x(4) y(4) cx(4) cy(4) flags(4).
           ARM commctrl (ListView etc.) handles WM_WINDOWPOSCHANGED to update
           sizeClient, trigger auto-arrange, and update scrollbars. */
        if (!lParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        WINDOWPOS* wp = (WINDOWPOS*)lParam;
        static uint32_t wp_emu_addr = 0x3F002100;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(wp_emu_addr)) emem.Alloc(wp_emu_addr, 0x1000);
        emem.Write32(wp_emu_addr + 0, (uint32_t)(uintptr_t)wp->hwnd);
        emem.Write32(wp_emu_addr + 4, (uint32_t)(uintptr_t)wp->hwndInsertAfter);
        emem.Write32(wp_emu_addr + 8, wp->x);
        emem.Write32(wp_emu_addr + 12, wp->y);
        emem.Write32(wp_emu_addr + 16, wp->cx);
        emem.Write32(wp_emu_addr + 20, wp->cy);
        emem.Write32(wp_emu_addr + 24, wp->flags);
        uint32_t arm_wndproc = it->second;
        uint32_t args[4] = {
            (uint32_t)(uintptr_t)hwnd, (uint32_t)msg,
            (uint32_t)wParam, (uint32_t)wp_emu_addr
        };
        uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);
        /* For WM_WINDOWPOSCHANGING, ARM code may modify the struct — copy back */
        if (msg == WM_WINDOWPOSCHANGING) {
            wp->x = (int)emem.Read32(wp_emu_addr + 8);
            wp->y = (int)emem.Read32(wp_emu_addr + 12);
            wp->cx = (int)emem.Read32(wp_emu_addr + 16);
            wp->cy = (int)emem.Read32(wp_emu_addr + 20);
            wp->flags = emem.Read32(wp_emu_addr + 24);
        }
        /* Don't call DefWindowProcW here — the ARM WndProc already calls it
           through its own DefWindowProcW thunk. */
        return (LRESULT)(intptr_t)(int32_t)result;
    }
    case WM_STYLECHANGING:
    case WM_STYLECHANGED: {
        /* Marshal STYLESTRUCT (8 bytes: styleOld + styleNew) into ARM memory.
           wParam = GWL_STYLE or GWL_EXSTYLE, lParam = STYLESTRUCT*.
           ARM commctrl (ListView, TreeView, etc.) handles these to update
           internal state when window styles change (e.g. view mode switching).
           For WM_STYLECHANGING, the ARM WndProc may modify styleNew to reject
           or alter proposed style changes — we must copy it back. */
        if (!lParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        STYLESTRUCT* ss = (STYLESTRUCT*)lParam;
        static uint32_t ss_emu_addr = 0x3F002200;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(ss_emu_addr)) emem.Alloc(ss_emu_addr, 0x1000);
        emem.Write32(ss_emu_addr + 0, ss->styleOld);
        emem.Write32(ss_emu_addr + 4, ss->styleNew);
        uint32_t arm_wndproc = it->second;
        uint32_t args[4] = {
            (uint32_t)(uintptr_t)hwnd, (uint32_t)msg,
            (uint32_t)wParam, (uint32_t)ss_emu_addr
        };
        uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);
        if (msg == WM_STYLECHANGING)
            ss->styleNew = emem.Read32(ss_emu_addr + 4);
        return (LRESULT)(intptr_t)(int32_t)result;
    }
    case WM_SETTEXT: {
        /* Marshal the string from native memory into ARM emulated memory.
           ARM controls (e.g. RichEdit20W) need WM_SETTEXT to update their
           internal text state and trigger repaint. */
        if (!lParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        const wchar_t* text = (const wchar_t*)lParam;
        size_t len = wcslen(text);
        static uint32_t st_emu_addr = 0x3F002400;
        EmulatedMemory& emem = s_instance->mem;
        uint32_t need = (uint32_t)((len + 1) * 2);
        if (need > 0x1000) need = 0x1000; /* cap at 4KB */
        if (!emem.IsValid(st_emu_addr)) emem.Alloc(st_emu_addr, 0x1000);
        uint32_t copyLen = (need / 2) - 1;
        for (uint32_t i = 0; i < copyLen; i++)
            emem.Write16(st_emu_addr + i * 2, text[i]);
        emem.Write16(st_emu_addr + copyLen * 2, 0);
        lParam = (LPARAM)st_emu_addr;
        break;
    }
    case WM_GETTEXT: {
        /* Marshal WM_GETTEXT: ARM code writes to ARM buffer, we copy back to native.
           wParam = max chars, lParam = native buffer pointer.
           Give ARM code a temp ARM buffer, then copy result back. */
        if (!lParam || !wParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        static uint32_t gt_emu_addr = 0x3F002800;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(gt_emu_addr)) emem.Alloc(gt_emu_addr, 0x1000);
        uint32_t maxChars = (uint32_t)wParam;
        if (maxChars > 2000) maxChars = 2000;
        /* Zero the ARM buffer */
        emem.Write16(gt_emu_addr, 0);
        LPARAM saved_native_buf = lParam;
        lParam = (LPARAM)gt_emu_addr;
        wParam = maxChars;
        /* Forward to ARM WndProc */
        uint32_t arm_wndproc = it->second;
        uint32_t args[4] = {
            (uint32_t)(uintptr_t)hwnd, (uint32_t)msg,
            (uint32_t)wParam, (uint32_t)lParam
        };
        uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);
        /* Copy ARM buffer back to native */
        wchar_t* native_buf = (wchar_t*)saved_native_buf;
        for (uint32_t i = 0; i < maxChars; i++) {
            native_buf[i] = (wchar_t)emem.Read16(gt_emu_addr + i * 2);
            if (native_buf[i] == 0) break;
        }
        native_buf[maxChars - 1] = 0;
        return (LRESULT)(intptr_t)(int32_t)result;
    }
    case WM_GETTEXTLENGTH:
        break; /* No pointers, safe to forward */
    case WM_CREATE:
    case WM_NCCREATE: {
        /* Marshal CREATESTRUCT into emulated memory (32-bit layout).
           Layout: lpCreateParams(0), hInstance(4), hMenu(8), hwndParent(12),
           cy(16), cx(20), y(24), x(28), style(32), lpszName(36),
           lpszClass(40), dwExStyle(44).
           Strings at offsets 36/40 MUST be valid ARM pointers — ARM controls
           (e.g. RichEdit) check lpszClass during Init and fail if NULL. */
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
        static uint32_t cs_emu_addr = 0x3F000000;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(cs_emu_addr)) emem.Alloc(cs_emu_addr, 0x1000);

        /* Marshal lpszName string (window title) at cs_emu_addr + 0x100.
           IS_INTRESOURCE: if the pointer is actually an ATOM (small integer
           via MAKEINTRESOURCE), don't dereference it as a string. */
        uint32_t name_ptr = 0;
        if (cs->lpszName && !IS_INTRESOURCE(cs->lpszName)) {
            name_ptr = cs_emu_addr + 0x100;
            const wchar_t* name = cs->lpszName;
            uint32_t off = 0;
            for (; name[off] && off < 200; off++)
                emem.Write16(name_ptr + off * 2, name[off]);
            emem.Write16(name_ptr + off * 2, 0);
        }
        /* Marshal lpszClass string at cs_emu_addr + 0x300 */
        uint32_t class_ptr = 0;
        if (cs->lpszClass && !IS_INTRESOURCE(cs->lpszClass)) {
            class_ptr = cs_emu_addr + 0x300;
            const wchar_t* cls = cs->lpszClass;
            uint32_t off = 0;
            for (; cls[off] && off < 200; off++)
                emem.Write16(class_ptr + off * 2, cls[off]);
            emem.Write16(class_ptr + off * 2, 0);
        }

        emem.Write32(cs_emu_addr + 0,  (uint32_t)(uintptr_t)cs->lpCreateParams);
        emem.Write32(cs_emu_addr + 4,  s_instance->emu_hinstance);
        emem.Write32(cs_emu_addr + 8,  0);
        emem.Write32(cs_emu_addr + 12, (uint32_t)(uintptr_t)cs->hwndParent);
        emem.Write32(cs_emu_addr + 16, cs->cy);
        emem.Write32(cs_emu_addr + 20, cs->cx);
        emem.Write32(cs_emu_addr + 24, cs->y);
        emem.Write32(cs_emu_addr + 28, cs->x);
        emem.Write32(cs_emu_addr + 32, cs->style);
        emem.Write32(cs_emu_addr + 36, name_ptr);
        emem.Write32(cs_emu_addr + 40, class_ptr);
        emem.Write32(cs_emu_addr + 44, cs->dwExStyle);
        lParam = (LPARAM)cs_emu_addr;
        break;
    }
    case WM_DRAWITEM: {
        /* Marshal DRAWITEMSTRUCT into emulated memory (64-bit -> 32-bit) */
        static uint32_t wdi_emu_addr = 0x3F002000;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(wdi_emu_addr)) emem.Alloc(wdi_emu_addr, 0x1000);
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        emem.Write32(wdi_emu_addr + 0,  dis->CtlType);
        emem.Write32(wdi_emu_addr + 4,  dis->CtlID);
        emem.Write32(wdi_emu_addr + 8,  dis->itemID);
        emem.Write32(wdi_emu_addr + 12, dis->itemAction);
        emem.Write32(wdi_emu_addr + 16, dis->itemState);
        emem.Write32(wdi_emu_addr + 20, (uint32_t)(uintptr_t)dis->hwndItem);
        emem.Write32(wdi_emu_addr + 24, (uint32_t)(uintptr_t)dis->hDC);
        emem.Write32(wdi_emu_addr + 28, dis->rcItem.left);
        emem.Write32(wdi_emu_addr + 32, dis->rcItem.top);
        emem.Write32(wdi_emu_addr + 36, dis->rcItem.right);
        emem.Write32(wdi_emu_addr + 40, dis->rcItem.bottom);
        emem.Write32(wdi_emu_addr + 44, (uint32_t)dis->itemData);
        lParam = (LPARAM)wdi_emu_addr;
        break;
    }
    case WM_MEASUREITEM: {
        /* Marshal MEASUREITEMSTRUCT into emulated memory (64-bit -> 32-bit) */
        static uint32_t wmi_emu_addr = 0x3F002500;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(wmi_emu_addr)) emem.Alloc(wmi_emu_addr, 0x1000);
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
        emem.Write32(wmi_emu_addr + 0,  mis->CtlType);
        emem.Write32(wmi_emu_addr + 4,  mis->CtlID);
        emem.Write32(wmi_emu_addr + 8,  mis->itemID);
        emem.Write32(wmi_emu_addr + 12, mis->itemWidth);
        emem.Write32(wmi_emu_addr + 16, mis->itemHeight);
        emem.Write32(wmi_emu_addr + 20, (uint32_t)mis->itemData);
        lParam = (LPARAM)wmi_emu_addr;
        break;
    }
    }

    /* WM_SETTINGCHANGE: Desktop Windows sends wParam=SPI, lParam=native string ptr.
       WinCE convention: lParam = SPI constant (for SPI_SETSIPINFO=0xE0).
       For other SPI values, lParam is a native 64-bit string pointer that would
       crash if truncated to 32-bit. Zero it out so ARM code gets the notification
       without dereferencing a bad pointer. */
    if (msg == WM_SETTINGCHANGE) {
        if (wParam == 0xE0 /* SPI_SETSIPINFO */)
            lParam = 0xE0;
        else
            lParam = 0;
    }

    uint32_t arm_wndproc = it->second;
    /* Debug: log key messages to ARM windows */
    if (msg == WM_PAINT || msg == WM_ERASEBKGND) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc: msg=0x%04X (%s) hwnd=0x%p class='%ls'\n",
            msg, msg == WM_PAINT ? "WM_PAINT" : "WM_ERASEBKGND", hwnd, cls);
    }
    if (msg == WM_CREATE || msg == WM_NCCREATE) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc: msg=0x%04X (%s) hwnd=0x%p class='%ls' arm_wndproc=0x%08X lP=0x%X\n",
            msg, msg == WM_CREATE ? "WM_CREATE" : "WM_NCCREATE", hwnd, cls, arm_wndproc, (uint32_t)lParam);
    }
    if (msg == WM_CLOSE || msg == WM_SYSCOMMAND || msg == WM_DESTROY) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc CLOSE-PATH: msg=0x%04X hwnd=0x%p class='%ls' wP=0x%X lP=0x%X\n",
            msg, hwnd, cls, (uint32_t)wParam, (uint32_t)lParam);
    }
    if (msg == WM_CHAR || msg == WM_KEYDOWN || msg == WM_SETTEXT ||
        msg == WM_LBUTTONDOWN || msg == WM_LBUTTONUP || msg == WM_CAPTURECHANGED ||
        msg == WM_SETFOCUS || msg == WM_KILLFOCUS ||
        msg == WM_INITMENUPOPUP || msg == WM_MENUSELECT) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc: msg=0x%04X hwnd=0x%p class='%ls' wP=0x%X lP=0x%X\n",
            msg, hwnd, cls, (uint32_t)wParam, (uint32_t)lParam);
    }
    if (msg == WM_NOTIFY) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        int32_t nmCode = 0;
        EmulatedMemory& emem = s_instance->mem;
        uint32_t lp32 = (uint32_t)lParam;
        if (lp32 && emem.IsValid(lp32 + 8))
            nmCode = (int32_t)emem.Read32(lp32 + 8);
        LOG(API, "[API] EmuWndProc WM_NOTIFY: hwnd=0x%p class='%ls' code=%d lP=0x%X\n",
            hwnd, cls, nmCode, lp32);
    }
    uint32_t args[4] = {
        (uint32_t)(uintptr_t)hwnd,
        (uint32_t)msg,
        (uint32_t)wParam,
        (uint32_t)lParam
    };

    uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);

    if (msg == WM_NOTIFY) {
        LOG(API, "[API] EmuWndProc WM_NOTIFY result=%u (0x%X)\n", result, result);
    }

    /* Copy back results from WM_MEASUREITEM */
    if (msg == WM_MEASUREITEM && native_lParam) {
        static uint32_t wmi_emu_addr = 0x3F002500;
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)native_lParam;
        EmulatedMemory& emem = s_instance->mem;
        mis->itemWidth = emem.Read32(wmi_emu_addr + 12);
        mis->itemHeight = emem.Read32(wmi_emu_addr + 16);
    }

    /* Sign-extend the 32-bit result to 64-bit LRESULT.  This is critical for
       WM_CTLCOLOR* messages which return HBRUSH handles — zero-extension would
       produce an invalid handle if the top bit of the 32-bit value is set. */
    return (LRESULT)(intptr_t)(int32_t)result;
}

/* ---------- WS_EX_CAPTIONOKBTN title bar button via window subclassing ---------- */

#define CAPTIONOK_SUBCLASS_ID 0xCE0F0001
#define HT_CAPTIONOK          0x0200      /* custom WM_NCHITTEST return value */

/* Per-window offset from the right edge of the window to the left edge of
   native title bar buttons (?, X).  Cached during InstallCaptionOk by probing
   WM_NCHITTEST, since SM_CXSIZE doesn't match the actual classic-mode button
   widths on Windows 10/11 with DWM disabled. */
/* Calculate the OK button rect in window (not screen) coordinates.
   Uses the same button-position formula as PaintThemedCaption so the
   OK button sits exactly to the left of the themed caption buttons. */
static RECT GetCaptionOkBtnRect(HWND hwnd) {
    int captH = GetSystemMetrics(SM_CYCAPTION);
    int padBorder = GetSystemMetrics(SM_CXPADDEDBORDER);
    int frame = GetSystemMetrics(SM_CXFRAME) + padBorder;
    int btnW = GetSystemMetrics(SM_CXSIZE) - 2;
    RECT wr;
    GetWindowRect(hwnd, &wr);
    int winW = wr.right - wr.left;
    int captRight = winW - frame;
    int border_top = GetSystemMetrics(SM_CYFRAME) + padBorder;

    /* Count native buttons — same logic as PaintThemedCaption */
    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    int btnX = captRight - 2;
    if (style & WS_SYSMENU) btnX -= btnW;
    if (exStyle & WS_EX_CONTEXTHELP) btnX -= btnW;
    if (style & WS_MAXIMIZEBOX) btnX -= btnW;
    if (style & WS_MINIMIZEBOX) btnX -= btnW;

    /* OK button goes immediately to the left of the leftmost native button */
    int okW = captH;
    RECT r;
    r.right = btnX;
    r.left  = r.right - okW;
    r.top   = border_top;
    r.bottom = r.top + captH;
    return r;
}

static void PaintCaptionOkBtn(HWND hwnd) {
    HDC hdc = GetWindowDC(hwnd);
    if (!hdc) return;
    bool active = (GetForegroundWindow() == hwnd);
    RECT r = GetCaptionOkBtnRect(hwnd);
    /* Button face */
    HBRUSH br = CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
    FillRect(hdc, &r, br);
    DeleteObject(br);
    DrawEdge(hdc, &r, BDR_RAISEDOUTER, BF_RECT);
    /* "OK" label */
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, GetSysColor(active ? COLOR_BTNTEXT : COLOR_GRAYTEXT));
    HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    DrawTextW(hdc, L"OK", 2, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, oldFont);
    ReleaseDC(hwnd, hdc);
}

LRESULT CALLBACK Win32Thunks::CaptionOkSubclassProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR refData)
{
    switch (msg) {
    case WM_NCHITTEST: {
        LRESULT def = DefSubclassProc(hwnd, msg, wParam, lParam);
        /* Only override hits in the caption area (not on native buttons) */
        if (def == HTCAPTION) {
            int ptx = (int)(short)LOWORD(lParam);
            int pty = (int)(short)HIWORD(lParam);
            RECT wr;
            GetWindowRect(hwnd, &wr);
            POINT pt = { ptx - wr.left, pty - wr.top };
            RECT okRect = GetCaptionOkBtnRect(hwnd);
            if (PtInRect(&okRect, pt))
                return HT_CAPTIONOK;
        }
        return def;
    }
    case WM_NCLBUTTONDOWN:
        if (wParam == HT_CAPTIONOK) {
            LOG(API, "[API] CaptionOK clicked on HWND=0x%p, posting WM_COMMAND(IDOK)\n", hwnd);
            PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), 0);
            return 0;
        }
        break;
    case WM_NCPAINT:
        DefSubclassProc(hwnd, msg, wParam, lParam);
        PaintCaptionOkBtn(hwnd);
        return 0;
    case WM_NCACTIVATE: {
        LRESULT r = DefSubclassProc(hwnd, msg, wParam, lParam);
        PaintCaptionOkBtn(hwnd);
        return r;
    }
    case WM_SIZE:
    case WM_MOVE: {
        LRESULT r = DefSubclassProc(hwnd, msg, wParam, lParam);
        PaintCaptionOkBtn(hwnd);
        return r;
    }
    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, CaptionOkSubclassProc, CAPTIONOK_SUBCLASS_ID);
        break;
    }
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

void Win32Thunks::InstallCaptionOk(HWND hwnd) {
    /* Disable DWM non-client rendering so our GDI title-bar painting is visible.
       Without this, DWM on Windows 10/11 paints over our custom NC area. */
    DWMNCRENDERINGPOLICY policy = DWMNCRP_DISABLED;
    DwmSetWindowAttribute(hwnd, DWMWA_NCRENDERING_POLICY, &policy, sizeof(policy));
    /* Force frame recalculation */
    SetWindowPos(hwnd, NULL, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

    SetWindowSubclass(hwnd, CaptionOkSubclassProc, CAPTIONOK_SUBCLASS_ID, 0);
    PaintCaptionOkBtn(hwnd);
}

void Win32Thunks::RemoveCaptionOk(HWND hwnd) {
    RemoveWindowSubclass(hwnd, CaptionOkSubclassProc, CAPTIONOK_SUBCLASS_ID);
    /* Re-enable DWM non-client rendering */
    DWMNCRENDERINGPOLICY policy = DWMNCRP_ENABLED;
    DwmSetWindowAttribute(hwnd, DWMWA_NCRENDERING_POLICY, &policy, sizeof(policy));
}

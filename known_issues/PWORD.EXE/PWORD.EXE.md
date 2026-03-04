# PWORD.EXE (Pocket Word / WordPad) - Known Issues

## 1. No text rendering in RichEdit control — FIXED

**Description**: PWORD.EXE launches and shows its main window with toolbar and RichEdit20W editing area. However, typing on the keyboard produced no visible text.

**Root cause**: CREATESTRUCT marshaling in `callbacks.cpp` set `lpszName` and `lpszClass` to NULL (0) when forwarding WM_CREATE/WM_NCCREATE to ARM WndProcs. The WinCE RichEdit control's `CTxtWinHost::Init` function (in riched20.dll at RVA 0x034BB8) checks `CREATESTRUCT.lpszClass` (offset 0x28) and returns 0 (failure) if NULL. This prevented the host object from being created and stored via `SetWindowLong(hwnd, 0, host)`, so all subsequent messages fell through to `DefWindowProc`.

**Fix** (`cerf/thunks/callbacks.cpp`): Marshal both `lpszName` and `lpszClass` wide strings from the native CREATESTRUCTW into ARM emulated memory, so the 32-bit CREATESTRUCT passed to ARM code contains valid pointers to the string data.

**Additional prerequisite fixes**:
- DLL search order (`dll_loader.cpp`): wince_sys_dir checked first to prefer uncompressed system DLLs over UPX-packed ones from the app's Office directory.
- Uncompressed `riched20.dll` (873KB, ARM/Thumb) bundled from the WinCE 5 ARMv4 build.
- Caret APIs (`misc.cpp`): `CreateCaret`, `ShowCaret`, `HideCaret`, `GetCaretBlinkTime` implemented with real Win32 calls.
- Scroll APIs (`window.cpp`): `ScrollWindowEx`, `SetScrollInfo`, `GetScrollInfo`, `SetScrollPos`, `SetScrollRange` implemented with ARM memory marshaling.
- Text/string thunks: `GetTextFaceW`, `WM_SETTEXT`/`WM_GETTEXT`/`WM_GETTEXTLENGTH` marshaling, `GetUserDefaultUILanguage`, `MonitorFromPoint`.

---

## 2. Registry.txt appearing in app working directory — NEEDS VERIFICATION

**Description**: User reported `registry.txt` appearing in the working directory of launched apps instead of in the cerf.exe directory.

**Investigation**: The registry code in `registry_impl.cpp` uses `GetModuleFileNameA(NULL, ...)` to derive the path, which should produce an absolute path next to cerf.exe. The code looks correct. May have been caused by a previous build or leftover files from testing.

**Status**: Could not reproduce. Needs re-testing with current build.

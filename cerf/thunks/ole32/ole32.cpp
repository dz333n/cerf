/*
 * OLE32.DLL thunks - Windows CE COM/OLE runtime
 *
 * Provides COM initialization, object creation, memory management,
 * GUID conversion, and marshalling stubs.
 */
#include "../win32_thunks.h"

void Win32Thunks::RegisterOle32Handlers() {
    /* COM Initialization — CoInitializeEx/CoUninitialize are registered in
       coredll/misc.cpp (WinCE exports them from coredll). These are OLE-specific. */
    Thunk("CoInitialize", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoInitialize(pvReserved=0x%08X) -> S_OK (stub)\n", regs[0]);
        regs[0] = 0; /* S_OK */
        return true;
    });
    Thunk("OleInitialize", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] OleInitialize(pvReserved=0x%08X) -> S_OK (stub)\n", regs[0]);
        regs[0] = 0; /* S_OK */
        return true;
    });
    Thunk("OleUninitialize", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] OleUninitialize() -> stub\n");
        /* void */
        return true;
    });

    /* Object Creation */
    Thunk("CoCreateInstance", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoCreateInstance(rclsid=0x%08X, pUnkOuter=0x%08X, dwClsCtx=0x%08X, riid=0x%08X) -> E_NOTIMPL (stub)\n",
               regs[0], regs[1], regs[2], regs[3]);
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });
    Thunk("CoCreateInstanceEx", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoCreateInstanceEx(...) -> E_NOTIMPL (stub)\n");
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });
    Thunk("CoGetClassObject", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoGetClassObject(...) -> E_NOTIMPL (stub)\n");
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });
    Thunk("CoCreateGuid", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoCreateGuid(pguid=0x%08X) -> S_OK (stub)\n", regs[0]);
        if (regs[0]) {
            /* Write a pseudo-random GUID */
            for (int i = 0; i < 16; i++)
                mem.Write8(regs[0] + i, (uint8_t)(rand() & 0xFF));
        }
        regs[0] = 0; /* S_OK */
        return true;
    });

    /* COM Memory Management */
    Thunk("CoTaskMemAlloc", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size = regs[0];
        printf("[THUNK] CoTaskMemAlloc(cb=%u)\n", size);
        /* Allocate from emulated heap */
        uint32_t ptr = 0;
        if (size > 0) {
            static uint32_t cotask_heap = 0x60000000;
            ptr = cotask_heap;
            cotask_heap += (size + 0xFFF) & ~0xFFF;
            mem.Alloc(ptr, (size + 0xFFF) & ~0xFFF);
        }
        regs[0] = ptr;
        return true;
    });
    Thunk("CoTaskMemFree", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoTaskMemFree(pv=0x%08X) -> stub\n", regs[0]);
        /* leak — no free tracking */
        return true;
    });
    Thunk("CoTaskMemRealloc", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoTaskMemRealloc(pv=0x%08X, cb=%u) -> stub (returns NULL)\n", regs[0], regs[1]);
        regs[0] = 0;
        return true;
    });
    Thunk("CoGetMalloc", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoGetMalloc(dwMemContext=%d, ppMalloc=0x%08X) -> E_NOTIMPL (stub)\n",
               regs[0], regs[1]);
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });

    /* GUID/String Conversion */
    Thunk("StringFromGUID2", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t guid_addr = regs[0], buf_addr = regs[1], cchMax = regs[2];
        printf("[THUNK] StringFromGUID2(rguid=0x%08X, lpsz=0x%08X, cchMax=%d)\n",
               guid_addr, buf_addr, cchMax);
        if (guid_addr && buf_addr && cchMax >= 39) {
            uint32_t d1 = mem.Read32(guid_addr);
            uint16_t d2 = mem.Read16(guid_addr + 4);
            uint16_t d3 = mem.Read16(guid_addr + 6);
            wchar_t buf[40];
            swprintf(buf, 40, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                     d1, d2, d3,
                     mem.Read8(guid_addr + 8), mem.Read8(guid_addr + 9),
                     mem.Read8(guid_addr + 10), mem.Read8(guid_addr + 11),
                     mem.Read8(guid_addr + 12), mem.Read8(guid_addr + 13),
                     mem.Read8(guid_addr + 14), mem.Read8(guid_addr + 15));
            for (int i = 0; buf[i] && i < (int)cchMax; i++)
                mem.Write16(buf_addr + i * 2, buf[i]);
            mem.Write16(buf_addr + 38 * 2, 0);
            regs[0] = 39;
        } else {
            regs[0] = 0;
        }
        return true;
    });
    Thunk("StringFromCLSID", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] StringFromCLSID(rclsid=0x%08X, lplpsz=0x%08X) -> E_NOTIMPL (stub)\n",
               regs[0], regs[1]);
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });
    Thunk("CLSIDFromString", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CLSIDFromString(lpsz=0x%08X, pclsid=0x%08X) -> E_NOTIMPL (stub)\n",
               regs[0], regs[1]);
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });
    Thunk("CLSIDFromProgID", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CLSIDFromProgID(lpszProgID=0x%08X, lpclsid=0x%08X) -> E_NOTIMPL (stub)\n",
               regs[0], regs[1]);
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });
    Thunk("ProgIDFromCLSID", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] ProgIDFromCLSID(clsid=0x%08X, lplpszProgID=0x%08X) -> E_NOTIMPL (stub)\n",
               regs[0], regs[1]);
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });

    /* Marshalling */
    Thunk("CoMarshalInterface", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoMarshalInterface(...) -> E_NOTIMPL (stub)\n");
        regs[0] = 0x80004001;
        return true;
    });
    Thunk("CoUnmarshalInterface", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoUnmarshalInterface(...) -> E_NOTIMPL (stub)\n");
        regs[0] = 0x80004001;
        return true;
    });

    /* Misc */
    Thunk("CoLockObjectExternal", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoLockObjectExternal(pUnk=0x%08X, fLock=%d, fLastUnlockReleases=%d) -> S_OK (stub)\n",
               regs[0], regs[1], regs[2]);
        regs[0] = 0; /* S_OK */
        return true;
    });
    Thunk("CoDisconnectObject", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoDisconnectObject(pUnk=0x%08X, dwReserved=%d) -> S_OK (stub)\n",
               regs[0], regs[1]);
        regs[0] = 0;
        return true;
    });
    Thunk("CoFreeUnusedLibraries", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoFreeUnusedLibraries() -> stub\n");
        return true;
    });
    Thunk("CoFileTimeNow", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] CoFileTimeNow(lpFileTime=0x%08X) -> S_OK (stub)\n", regs[0]);
        if (regs[0]) {
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            mem.Write32(regs[0], ft.dwLowDateTime);
            mem.Write32(regs[0] + 4, ft.dwHighDateTime);
        }
        regs[0] = 0;
        return true;
    });
    Thunk("ReleaseStgMedium", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] ReleaseStgMedium(pmedium=0x%08X) -> stub\n", regs[0]);
        return true;
    });
}

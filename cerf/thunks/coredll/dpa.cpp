#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Dynamic Pointer Array (DPA) thunks — coredll re-exports from commctrl.
   Used internally by ListView, TreeView, and other common controls.

   HDPA is a native heap pointer (64-bit on x64) that can't survive 32-bit
   truncation. We maintain a map of fake 32-bit handles -> real HDPA. */
#include "../win32_thunks.h"
#include "../../log.h"
#include <commctrl.h>
#include <dpa_dsa.h>

static std::map<uint32_t, HDPA> dpa_handle_map;
static uint32_t dpa_next_handle = 0xDA000000;

static uint32_t WrapDpa(HDPA h) {
    if (!h) return 0;
    uint32_t fake = dpa_next_handle++;
    dpa_handle_map[fake] = h;
    return fake;
}

static HDPA UnwrapDpa(uint32_t fake) {
    if (!fake) return NULL;
    auto it = dpa_handle_map.find(fake);
    return (it != dpa_handle_map.end()) ? it->second : NULL;
}

static void RemoveDpa(uint32_t fake) {
    dpa_handle_map.erase(fake);
}

void Win32Thunks::RegisterDpaHandlers() {
    Thunk("DPA_Create", 1837, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = DPA_Create((int)regs[0]);
        regs[0] = WrapDpa(h);
        LOG(THUNK, "[THUNK] DPA_Create(cGrow=%d) -> 0x%08X\n", (int)regs[0], regs[0]);
        return true;
    });
    Thunk("DPA_CreateEx", 1838, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = DPA_Create((int)regs[0]);
        uint32_t fake = WrapDpa(h);
        LOG(THUNK, "[THUNK] DPA_CreateEx(cGrow=%d) -> 0x%08X\n", (int)regs[0], fake);
        regs[0] = fake;
        return true;
    });
    Thunk("DPA_Clone", 1839, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA src = UnwrapDpa(regs[0]);
        HDPA dst = UnwrapDpa(regs[1]);
        HDPA h = DPA_Clone(src, dst);
        regs[0] = dst ? regs[1] : WrapDpa(h);
        return true;
    });
    Thunk("DPA_DeleteAllPtrs", 1840, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = UnwrapDpa(regs[0]);
        regs[0] = h ? DPA_DeleteAllPtrs(h) : FALSE;
        return true;
    });
    Thunk("DPA_DeletePtr", 1841, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = UnwrapDpa(regs[0]);
        void* ret = h ? DPA_DeletePtr(h, (int)regs[1]) : NULL;
        regs[0] = (uint32_t)(uintptr_t)ret;
        return true;
    });
    Thunk("DPA_Destroy", 1842, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = UnwrapDpa(regs[0]);
        BOOL ret = h ? DPA_Destroy(h) : FALSE;
        RemoveDpa(regs[0]);
        regs[0] = ret;
        return true;
    });
    Thunk("DPA_DestroyCallback", 1843, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = UnwrapDpa(regs[0]);
        LOG(THUNK, "[THUNK] DPA_DestroyCallback(0x%08X) -> destroying without callback\n", regs[0]);
        if (h) DPA_Destroy(h);
        RemoveDpa(regs[0]);
        regs[0] = 1;
        return true;
    });
    Thunk("DPA_EnumCallback", 1844, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] DPA_EnumCallback(0x%08X) -> stub\n", regs[0]);
        regs[0] = 0;
        return true;
    });
    Thunk("DPA_GetPtr", 1845, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = UnwrapDpa(regs[0]);
        void* ret = h ? DPA_GetPtr(h, (int)regs[1]) : NULL;
        regs[0] = (uint32_t)(uintptr_t)ret;
        return true;
    });
    Thunk("DPA_GetPtrIndex", 1846, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = UnwrapDpa(regs[0]);
        int ret = h ? DPA_GetPtrIndex(h, (void*)(uintptr_t)regs[1]) : -1;
        regs[0] = (uint32_t)ret;
        return true;
    });
    Thunk("DPA_Grow", 1847, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = UnwrapDpa(regs[0]);
        regs[0] = h ? DPA_Grow(h, (int)regs[1]) : FALSE;
        return true;
    });
    Thunk("DPA_InsertPtr", 1848, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = UnwrapDpa(regs[0]);
        int ret = h ? DPA_InsertPtr(h, (int)regs[1], (void*)(uintptr_t)regs[2]) : -1;
        regs[0] = (uint32_t)ret;
        return true;
    });
    Thunk("DPA_Search", 1849, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] DPA_Search(...) -> stub returning -1\n");
        regs[0] = (uint32_t)-1;
        return true;
    });
    Thunk("DPA_SetPtr", 1850, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDPA h = UnwrapDpa(regs[0]);
        regs[0] = h ? DPA_SetPtr(h, (int)regs[1], (void*)(uintptr_t)regs[2]) : FALSE;
        return true;
    });
    Thunk("DPA_Sort", 1851, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] DPA_Sort(...) -> stub returning TRUE\n");
        regs[0] = 1;
        return true;
    });
}

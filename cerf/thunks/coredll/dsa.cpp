#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Dynamic Structure Array (DSA) thunks — coredll re-exports from commctrl.
   Used internally by ListView, TreeView, Header, and other common controls.

   IMPORTANT: The ARM commctrl code reads DSA struct fields directly from
   memory (hdsa->cItem, hdsa->cbItem, hdsa->aItem), so the DSA must live
   in emulated memory.

   WinCE DSA struct layout (24 bytes):
     +0  cItem      (int32)  — current item count
     +4  aItem      (uint32) — pointer to item array in emulated memory
     +8  cItemAlloc (int32)  — allocated capacity
     +12 cbItem     (int32)  — bytes per item
     +16 cItemGrow  (int32)  — growth increment
     +20 magic      (uint32) — magic value (unused, set to 0)
*/
#include "../win32_thunks.h"
#include "../../log.h"

static constexpr uint32_t DSA_STRUCT_SIZE = 24;

/* Simple bump allocator for DSA structs and arrays in emulated memory */
static uint32_t dsa_heap_base = 0xD5000000;
static uint32_t dsa_heap_cur  = 0xD5000000;
static constexpr uint32_t DSA_HEAP_SIZE = 0x00200000; /* 2 MB */

static uint32_t DsaAlloc(EmulatedMemory& mem, uint32_t size) {
    size = (size + 3) & ~3u;
    if (dsa_heap_cur + size > dsa_heap_base + DSA_HEAP_SIZE) {
        LOG_ERR("[DSA] Out of DSA heap space!\n");
        return 0;
    }
    uint32_t addr = dsa_heap_cur;
    if (!mem.IsValid(addr)) {
        uint32_t page_base = addr & ~0xFFFFu;
        mem.Alloc(page_base, 0x10000);
    }
    uint32_t end_page = (addr + size) & ~0xFFFFu;
    if (!mem.IsValid(end_page) && end_page < dsa_heap_base + DSA_HEAP_SIZE) {
        mem.Alloc(end_page, 0x10000);
    }
    dsa_heap_cur = addr + size;
    return addr;
}

/* Read DSA fields from emulated memory */
static int DsaGetCItem(EmulatedMemory& mem, uint32_t hdsa) {
    return (int)mem.Read32(hdsa + 0);
}
static uint32_t DsaGetAItem(EmulatedMemory& mem, uint32_t hdsa) {
    return mem.Read32(hdsa + 4);
}
static int DsaGetCItemAlloc(EmulatedMemory& mem, uint32_t hdsa) {
    return (int)mem.Read32(hdsa + 8);
}
static int DsaGetCbItem(EmulatedMemory& mem, uint32_t hdsa) {
    return (int)mem.Read32(hdsa + 12);
}
static int DsaGetCItemGrow(EmulatedMemory& mem, uint32_t hdsa) {
    return (int)mem.Read32(hdsa + 16);
}

/* Write DSA fields */
static void DsaSetCItem(EmulatedMemory& mem, uint32_t hdsa, int v) {
    mem.Write32(hdsa + 0, (uint32_t)v);
}
static void DsaSetAItem(EmulatedMemory& mem, uint32_t hdsa, uint32_t v) {
    mem.Write32(hdsa + 4, v);
}
static void DsaSetCItemAlloc(EmulatedMemory& mem, uint32_t hdsa, int v) {
    mem.Write32(hdsa + 8, (uint32_t)v);
}

/* Grow item array to hold at least newCap items */
static bool DsaGrow(EmulatedMemory& mem, uint32_t hdsa, int newCap) {
    int curAlloc = DsaGetCItemAlloc(mem, hdsa);
    if (newCap <= curAlloc) return true;
    int cbItem = DsaGetCbItem(mem, hdsa);
    int grow = DsaGetCItemGrow(mem, hdsa);
    if (grow <= 0) grow = 4;
    newCap = ((newCap + grow - 1) / grow) * grow;
    uint32_t newArray = DsaAlloc(mem, newCap * cbItem);
    if (!newArray) return false;
    /* Copy existing items */
    int cItem = DsaGetCItem(mem, hdsa);
    uint32_t oldArray = DsaGetAItem(mem, hdsa);
    if (cItem > 0 && oldArray) {
        uint8_t* src = mem.Translate(oldArray);
        uint8_t* dst = mem.Translate(newArray);
        if (src && dst) memcpy(dst, src, (size_t)cItem * cbItem);
    }
    DsaSetAItem(mem, hdsa, newArray);
    DsaSetCItemAlloc(mem, hdsa, newCap);
    return true;
}

void Win32Thunks::RegisterDsaHandlers() {
    /* DSA_Create(cbItem, cItemGrow) -> HDSA */
    Thunk("DSA_Create", 1852, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int cbItem = (int)regs[0];
        int cGrow = (int)regs[1];
        if (cbItem <= 0) cbItem = 4;
        if (cGrow <= 0) cGrow = 4;
        uint32_t hdsa = DsaAlloc(mem, DSA_STRUCT_SIZE);
        if (!hdsa) { regs[0] = 0; return true; }
        DsaSetCItem(mem, hdsa, 0);
        DsaSetAItem(mem, hdsa, 0);
        DsaSetCItemAlloc(mem, hdsa, 0);
        mem.Write32(hdsa + 12, (uint32_t)cbItem);
        mem.Write32(hdsa + 16, (uint32_t)cGrow);
        mem.Write32(hdsa + 20, 0); /* magic */
        DsaGrow(mem, hdsa, cGrow);
        LOG(API, "[API] DSA_Create(cbItem=%d, cGrow=%d) -> 0x%08X\n",
            cbItem, cGrow, hdsa);
        regs[0] = hdsa;
        return true;
    });

    /* DSA_Clone(hdsa) -> HDSA */
    Thunk("DSA_Clone", 1853, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t src = regs[0];
        int cItem = DsaGetCItem(mem, src);
        int cbItem = DsaGetCbItem(mem, src);
        int cGrow = DsaGetCItemGrow(mem, src);
        uint32_t hdsa = DsaAlloc(mem, DSA_STRUCT_SIZE);
        if (!hdsa) { regs[0] = 0; return true; }
        DsaSetCItem(mem, hdsa, 0);
        DsaSetAItem(mem, hdsa, 0);
        DsaSetCItemAlloc(mem, hdsa, 0);
        mem.Write32(hdsa + 12, (uint32_t)cbItem);
        mem.Write32(hdsa + 16, (uint32_t)cGrow);
        mem.Write32(hdsa + 20, 0);
        DsaGrow(mem, hdsa, cItem > 0 ? cItem : cGrow);
        if (cItem > 0) {
            uint32_t srcArray = DsaGetAItem(mem, src);
            uint32_t dstArray = DsaGetAItem(mem, hdsa);
            uint8_t* sp = mem.Translate(srcArray);
            uint8_t* dp = mem.Translate(dstArray);
            if (sp && dp) memcpy(dp, sp, (size_t)cItem * cbItem);
            DsaSetCItem(mem, hdsa, cItem);
        }
        regs[0] = hdsa;
        return true;
    });

    /* DSA_DeleteAllItems(hdsa) -> BOOL */
    Thunk("DSA_DeleteAllItems", 1854, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        DsaSetCItem(mem, regs[0], 0);
        regs[0] = TRUE;
        return true;
    });

    /* DSA_DeleteItem(hdsa, i) -> BOOL */
    Thunk("DSA_DeleteItem", 1855, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdsa = regs[0];
        int idx = (int)regs[1];
        int cItem = DsaGetCItem(mem, hdsa);
        int cbItem = DsaGetCbItem(mem, hdsa);
        if (idx < 0 || idx >= cItem) { regs[0] = FALSE; return true; }
        if (idx < cItem - 1) {
            uint32_t arr = DsaGetAItem(mem, hdsa);
            uint8_t* base = mem.Translate(arr);
            if (base)
                memmove(base + idx * cbItem,
                        base + (idx + 1) * cbItem,
                        (size_t)(cItem - idx - 1) * cbItem);
        }
        DsaSetCItem(mem, hdsa, cItem - 1);
        regs[0] = TRUE;
        return true;
    });

    /* DSA_Destroy(hdsa) -> BOOL */
    Thunk("DSA_Destroy", 1856, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Memory is bump-allocated, no individual free needed */
        regs[0] = TRUE;
        return true;
    });

    /* DSA_DestroyCallback(hdsa, pfnCB, pData) */
    Thunk("DSA_DestroyCallback", 1857, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] DSA_DestroyCallback(0x%08X) -> destroying without callback\n", regs[0]);
        regs[0] = 0;
        return true;
    });

    /* DSA_EnumCallback(hdsa, pfnCB, pData) */
    Thunk("DSA_EnumCallback", 1858, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdsa = regs[0];
        uint32_t pfnCB = regs[1];
        uint32_t pData = regs[2];
        int cItem = DsaGetCItem(mem, hdsa);
        int cbItem = DsaGetCbItem(mem, hdsa);
        uint32_t arr = DsaGetAItem(mem, hdsa);
        if (!callback_executor || !pfnCB) { regs[0] = 0; return true; }
        for (int i = 0; i < cItem; i++) {
            uint32_t itemAddr = arr + i * cbItem;
            uint32_t args[2] = { itemAddr, pData };
            uint32_t ret = callback_executor(pfnCB, args, 2);
            if (!ret) break;
        }
        regs[0] = 1;
        return true;
    });

    /* DSA_GetItem(hdsa, i, pItem) -> BOOL */
    Thunk("DSA_GetItem", 1859, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdsa = regs[0];
        int idx = (int)regs[1];
        uint32_t pItem = regs[2];
        int cItem = DsaGetCItem(mem, hdsa);
        int cbItem = DsaGetCbItem(mem, hdsa);
        if (idx < 0 || idx >= cItem || !pItem) { regs[0] = FALSE; return true; }
        uint32_t arr = DsaGetAItem(mem, hdsa);
        uint8_t* src = mem.Translate(arr + idx * cbItem);
        uint8_t* dst = mem.Translate(pItem);
        if (src && dst) memcpy(dst, src, cbItem);
        regs[0] = TRUE;
        return true;
    });

    /* DSA_GetItemPtr(hdsa, i) -> void* */
    Thunk("DSA_GetItemPtr", 1860, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdsa = regs[0];
        int idx = (int)regs[1];
        int cItem = DsaGetCItem(mem, hdsa);
        int cbItem = DsaGetCbItem(mem, hdsa);
        if (idx < 0 || idx >= cItem) { regs[0] = 0; return true; }
        uint32_t arr = DsaGetAItem(mem, hdsa);
        regs[0] = arr + idx * cbItem;
        return true;
    });

    /* DSA_Grow(hdsa, cNewItems) -> BOOL */
    Thunk("DSA_Grow", 1861, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = DsaGrow(mem, regs[0], (int)regs[1]) ? TRUE : FALSE;
        return true;
    });

    /* DSA_InsertItem(hdsa, i, pItem) -> int */
    Thunk("DSA_InsertItem", 1862, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdsa = regs[0];
        int idx = (int)regs[1];
        uint32_t pItem = regs[2];
        int cItem = DsaGetCItem(mem, hdsa);
        int cbItem = DsaGetCbItem(mem, hdsa);
        /* DA_LAST = 0x7FFFFFFF means append */
        if (idx < 0 || idx > cItem) idx = cItem;
        /* Grow if needed */
        if (cItem >= DsaGetCItemAlloc(mem, hdsa)) {
            if (!DsaGrow(mem, hdsa, cItem + 1)) {
                regs[0] = (uint32_t)-1;
                return true;
            }
        }
        uint32_t arr = DsaGetAItem(mem, hdsa);
        uint8_t* base = mem.Translate(arr);
        if (!base) { regs[0] = (uint32_t)-1; return true; }
        /* Shift items up to make room */
        if (idx < cItem) {
            memmove(base + (idx + 1) * cbItem,
                    base + idx * cbItem,
                    (size_t)(cItem - idx) * cbItem);
        }
        /* Copy item data from emulated memory */
        if (pItem) {
            uint8_t* src = mem.Translate(pItem);
            if (src) memcpy(base + idx * cbItem, src, cbItem);
        } else {
            memset(base + idx * cbItem, 0, cbItem);
        }
        DsaSetCItem(mem, hdsa, cItem + 1);
        regs[0] = (uint32_t)idx;
        return true;
    });

    /* DSA_Search(hdsa, pFind, iStart, pfnCmp, lParam, options) -> int */
    Thunk("DSA_Search", 1863, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] DSA_Search(...) -> stub returning -1\n");
        regs[0] = (uint32_t)-1;
        return true;
    });

    /* DSA_SetItem(hdsa, i, pItem) -> BOOL */
    Thunk("DSA_SetItem", 1864, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdsa = regs[0];
        int idx = (int)regs[1];
        uint32_t pItem = regs[2];
        int cItem = DsaGetCItem(mem, hdsa);
        int cbItem = DsaGetCbItem(mem, hdsa);
        if (idx < 0 || idx >= cItem || !pItem) { regs[0] = FALSE; return true; }
        uint32_t arr = DsaGetAItem(mem, hdsa);
        uint8_t* dst = mem.Translate(arr + idx * cbItem);
        uint8_t* src = mem.Translate(pItem);
        if (dst && src) memcpy(dst, src, cbItem);
        regs[0] = TRUE;
        return true;
    });

    /* DSA_SetRange(hdsa, i, cItems, pItems) -> BOOL */
    Thunk("DSA_SetRange", 1865, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] DSA_SetRange(...) -> stub returning TRUE\n");
        regs[0] = TRUE;
        return true;
    });

    /* DSA_Sort(hdsa, pfnCmp, lParam) -> BOOL */
    Thunk("DSA_Sort", 1866, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] DSA_Sort(...) -> stub returning TRUE\n");
        regs[0] = TRUE;
        return true;
    });
}

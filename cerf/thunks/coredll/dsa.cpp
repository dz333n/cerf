#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Dynamic Structure Array (DSA) thunks — coredll re-exports from commctrl.
   Used internally by ListView, TreeView, and other common controls.

   Unlike DPA (which stores pointers), DSA stores fixed-size data items.
   Items must live in emulated memory because ARM code dereferences pointers
   returned by DSA_GetItemPtr. We manage DSA storage entirely in emulated
   memory, with metadata tracked on the native side. */
#include "../win32_thunks.h"
#include "../../log.h"

struct EmuDsa {
    int cbItem;     /* Size of each item in bytes */
    int cGrow;      /* Growth increment */
    int cItems;     /* Current item count */
    int cAlloc;     /* Allocated capacity */
    uint32_t emuBase; /* Item array base address in emulated memory */
};

static std::map<uint32_t, EmuDsa> dsa_map;
static uint32_t dsa_next_handle = 0xD5A00000;
static uint32_t dsa_mem_next = 0xD5000000;

static uint32_t AllocDsaMem(EmulatedMemory& mem, uint32_t size) {
    uint32_t aligned = (size + 0xFFF) & ~0xFFF;
    uint32_t addr = dsa_mem_next;
    mem.Alloc(addr, aligned);
    dsa_mem_next += aligned;
    return addr;
}

/* Grow the DSA to hold at least newCap items. Allocates a new emulated
   memory block and copies existing items over. */
static bool GrowDsa(EmuDsa& dsa, EmulatedMemory& mem, int newCap) {
    if (newCap <= dsa.cAlloc) return true;
    /* Round up to next multiple of cGrow */
    int grow = dsa.cGrow > 0 ? dsa.cGrow : 4;
    newCap = ((newCap + grow - 1) / grow) * grow;
    uint32_t newBase = AllocDsaMem(mem, newCap * dsa.cbItem);
    if (!newBase) return false;
    /* Copy existing items */
    if (dsa.cItems > 0 && dsa.emuBase) {
        uint8_t* src = mem.Translate(dsa.emuBase);
        uint8_t* dst = mem.Translate(newBase);
        if (src && dst)
            memcpy(dst, src, (size_t)dsa.cItems * dsa.cbItem);
    }
    dsa.emuBase = newBase;
    dsa.cAlloc = newCap;
    return true;
}

void Win32Thunks::RegisterDsaHandlers() {
    /* DSA_Create(cbItem, cItemGrow) -> HDSA */
    Thunk("DSA_Create", 1852, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int cbItem = (int)regs[0];
        int cGrow = (int)regs[1];
        if (cbItem <= 0) cbItem = 4;
        if (cGrow <= 0) cGrow = 4;
        uint32_t handle = dsa_next_handle++;
        EmuDsa dsa = { cbItem, cGrow, 0, 0, 0 };
        GrowDsa(dsa, mem, cGrow);
        dsa_map[handle] = dsa;
        LOG(THUNK, "[THUNK] DSA_Create(cbItem=%d, cGrow=%d) -> 0x%08X\n",
            cbItem, cGrow, handle);
        regs[0] = handle;
        return true;
    });

    /* DSA_Clone(hdsa) -> HDSA */
    Thunk("DSA_Clone", 1853, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        auto it = dsa_map.find(regs[0]);
        if (it == dsa_map.end()) { regs[0] = 0; return true; }
        EmuDsa& src = it->second;
        uint32_t handle = dsa_next_handle++;
        EmuDsa clone = { src.cbItem, src.cGrow, src.cItems, 0, 0 };
        GrowDsa(clone, mem, src.cItems);
        if (src.cItems > 0) {
            uint8_t* sp = mem.Translate(src.emuBase);
            uint8_t* dp = mem.Translate(clone.emuBase);
            if (sp && dp) memcpy(dp, sp, (size_t)src.cItems * src.cbItem);
        }
        dsa_map[handle] = clone;
        regs[0] = handle;
        return true;
    });

    /* DSA_DeleteAllItems(hdsa) -> BOOL */
    Thunk("DSA_DeleteAllItems", 1854, [](uint32_t* regs, EmulatedMemory&) -> bool {
        auto it = dsa_map.find(regs[0]);
        if (it != dsa_map.end()) it->second.cItems = 0;
        regs[0] = TRUE;
        return true;
    });

    /* DSA_DeleteItem(hdsa, i) -> BOOL */
    Thunk("DSA_DeleteItem", 1855, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        auto it = dsa_map.find(regs[0]);
        if (it == dsa_map.end()) { regs[0] = FALSE; return true; }
        EmuDsa& dsa = it->second;
        int idx = (int)regs[1];
        if (idx < 0 || idx >= dsa.cItems) { regs[0] = FALSE; return true; }
        /* Shift items down */
        if (idx < dsa.cItems - 1) {
            uint8_t* base = mem.Translate(dsa.emuBase);
            if (base)
                memmove(base + idx * dsa.cbItem,
                        base + (idx + 1) * dsa.cbItem,
                        (size_t)(dsa.cItems - idx - 1) * dsa.cbItem);
        }
        dsa.cItems--;
        regs[0] = TRUE;
        return true;
    });

    /* DSA_Destroy(hdsa) -> BOOL */
    Thunk("DSA_Destroy", 1856, [](uint32_t* regs, EmulatedMemory&) -> bool {
        dsa_map.erase(regs[0]);
        regs[0] = TRUE;
        return true;
    });

    /* DSA_DestroyCallback(hdsa, pfnCB, pData) */
    Thunk("DSA_DestroyCallback", 1857, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] DSA_DestroyCallback(0x%08X) -> destroying without callback\n", regs[0]);
        dsa_map.erase(regs[0]);
        regs[0] = 0;
        return true;
    });

    /* DSA_EnumCallback(hdsa, pfnCB, pData) */
    Thunk("DSA_EnumCallback", 1858, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] DSA_EnumCallback(0x%08X) -> stub\n", regs[0]);
        regs[0] = 0;
        return true;
    });

    /* DSA_GetItem(hdsa, i, pItem) -> BOOL */
    Thunk("DSA_GetItem", 1859, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        auto it = dsa_map.find(regs[0]);
        if (it == dsa_map.end()) { regs[0] = FALSE; return true; }
        EmuDsa& dsa = it->second;
        int idx = (int)regs[1];
        uint32_t pItem = regs[2];
        if (idx < 0 || idx >= dsa.cItems || !pItem) { regs[0] = FALSE; return true; }
        uint8_t* src = mem.Translate(dsa.emuBase + idx * dsa.cbItem);
        uint8_t* dst = mem.Translate(pItem);
        if (src && dst) memcpy(dst, src, dsa.cbItem);
        regs[0] = TRUE;
        return true;
    });

    /* DSA_GetItemPtr(hdsa, i) -> void* */
    Thunk("DSA_GetItemPtr", 1860, [](uint32_t* regs, EmulatedMemory&) -> bool {
        auto it = dsa_map.find(regs[0]);
        if (it == dsa_map.end()) { regs[0] = 0; return true; }
        EmuDsa& dsa = it->second;
        int idx = (int)regs[1];
        if (idx < 0 || idx >= dsa.cItems) { regs[0] = 0; return true; }
        regs[0] = dsa.emuBase + idx * dsa.cbItem;
        return true;
    });

    /* DSA_Grow(hdsa, cNewItems) -> BOOL */
    Thunk("DSA_Grow", 1861, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        auto it = dsa_map.find(regs[0]);
        if (it == dsa_map.end()) { regs[0] = FALSE; return true; }
        regs[0] = GrowDsa(it->second, mem, (int)regs[1]) ? TRUE : FALSE;
        return true;
    });

    /* DSA_InsertItem(hdsa, i, pItem) -> int */
    Thunk("DSA_InsertItem", 1862, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        auto it = dsa_map.find(regs[0]);
        if (it == dsa_map.end()) { regs[0] = (uint32_t)-1; return true; }
        EmuDsa& dsa = it->second;
        int idx = (int)regs[1];
        uint32_t pItem = regs[2];
        /* DA_LAST = 0x7FFFFFFF means append */
        if (idx < 0 || idx > dsa.cItems) idx = dsa.cItems;
        /* Grow if needed */
        if (dsa.cItems >= dsa.cAlloc) {
            if (!GrowDsa(dsa, mem, dsa.cItems + 1)) {
                regs[0] = (uint32_t)-1;
                return true;
            }
        }
        uint8_t* base = mem.Translate(dsa.emuBase);
        if (!base) { regs[0] = (uint32_t)-1; return true; }
        /* Shift items up to make room */
        if (idx < dsa.cItems) {
            memmove(base + (idx + 1) * dsa.cbItem,
                    base + idx * dsa.cbItem,
                    (size_t)(dsa.cItems - idx) * dsa.cbItem);
        }
        /* Copy item data from emulated memory */
        if (pItem) {
            uint8_t* src = mem.Translate(pItem);
            if (src) memcpy(base + idx * dsa.cbItem, src, dsa.cbItem);
        } else {
            memset(base + idx * dsa.cbItem, 0, dsa.cbItem);
        }
        dsa.cItems++;
        regs[0] = (uint32_t)idx;
        return true;
    });

    /* DSA_Search(hdsa, pFind, iStart, pfnCmp, lParam, options) -> int */
    Thunk("DSA_Search", 1863, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] DSA_Search(...) -> stub returning -1\n");
        regs[0] = (uint32_t)-1;
        return true;
    });

    /* DSA_SetItem(hdsa, i, pItem) -> BOOL */
    Thunk("DSA_SetItem", 1864, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        auto it = dsa_map.find(regs[0]);
        if (it == dsa_map.end()) { regs[0] = FALSE; return true; }
        EmuDsa& dsa = it->second;
        int idx = (int)regs[1];
        uint32_t pItem = regs[2];
        if (idx < 0 || idx >= dsa.cItems || !pItem) { regs[0] = FALSE; return true; }
        uint8_t* dst = mem.Translate(dsa.emuBase + idx * dsa.cbItem);
        uint8_t* src = mem.Translate(pItem);
        if (dst && src) memcpy(dst, src, dsa.cbItem);
        regs[0] = TRUE;
        return true;
    });

    /* DSA_SetRange(hdsa, i, cItems, pItems) -> BOOL */
    Thunk("DSA_SetRange", 1865, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] DSA_SetRange(...) -> stub returning TRUE\n");
        regs[0] = TRUE;
        return true;
    });

    /* DSA_Sort(hdsa, pfnCmp, lParam) -> BOOL */
    Thunk("DSA_Sort", 1866, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] DSA_Sort(...) -> stub returning TRUE\n");
        regs[0] = TRUE;
        return true;
    });
}

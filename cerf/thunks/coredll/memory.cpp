/* Memory allocation thunks: VirtualAlloc, Heap*, Local*, malloc/free */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

/* All allocator bases MUST be below 0x02000000 (32MB slot boundary).
   WinCE ARM code applies slot masking (AND addr, #0x01FFFFFF) to pointers.
   Any address >= 0x02000000 gets corrupted to a different address. */

void Win32Thunks::RegisterMemoryHandlers() {
    Thunk("VirtualAlloc", 524, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr_arg = regs[0], size = regs[1];
        static uint32_t next_valloc = 0x00200000;
        uint32_t base = (addr_arg != 0) ? addr_arg : next_valloc;
        uint8_t* ptr = mem.Alloc(base, size, regs[3]);
        if (ptr) {
            if (addr_arg == 0) next_valloc = base + ((size + 0xFFF) & ~0xFFF);
            regs[0] = base;
        } else { regs[0] = 0; }
        LOG(API, "[API] VirtualAlloc(0x%08X, 0x%X) -> 0x%08X\n", addr_arg, size, regs[0]);
        return true;
    });
    Thunk("VirtualFree", 525, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[STUB] VirtualFree(0x%08X) -> 1 (leak)\n", regs[0]);
        regs[0] = 1; return true;
    });
    Thunk("LocalAlloc", 33, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t flags = regs[0], size = regs[1];
        static uint32_t next_local = 0x00800000;
        uint8_t* ptr = mem.Alloc(next_local, size);
        if (ptr) {
            if (flags & 0x40) memset(ptr, 0, size);
            regs[0] = next_local;
            next_local += (size + 0xFFF) & ~0xFFF;
        } else { regs[0] = 0; }
        return true;
    });
    thunk_handlers["LocalAllocTrace"] = thunk_handlers["LocalAlloc"];
    Thunk("LocalReAlloc", 34, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[0], new_size = regs[1], flags = regs[2];
        static uint32_t next_lrealloc = 0x00900000;
        uint8_t* new_host = mem.Alloc(next_lrealloc, new_size);
        /* LMEM_ZEROINIT: zero new buffer BEFORE copying old data on top */
        if ((flags & 0x40) && new_host) memset(new_host, 0, new_size);
        uint8_t* old_host = mem.Translate(old_ptr);
        if (old_host && new_host) memcpy(new_host, old_host, std::min(new_size, (uint32_t)0x1000));
        regs[0] = next_lrealloc;
        next_lrealloc += (new_size + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("LocalFree", 36, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });
    Thunk("LocalSize", 35, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[STUB] LocalSize(0x%08X) -> 0x1000\n", regs[0]);
        regs[0] = 0x1000; return true;
    });
    Thunk("GetProcessHeap", 50, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0xDEAD0001; return true;
    });
    auto heapAllocImpl = [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size_arg = regs[2];
        static uint32_t next_heap = 0x01000000;
        mem.Alloc(next_heap, size_arg);
        regs[0] = next_heap;
        next_heap += (size_arg + 0xFFF) & ~0xFFF;
        return true;
    };
    Thunk("HeapAlloc", 46, heapAllocImpl);
    Thunk("HeapAllocTrace", 20, heapAllocImpl);
    Thunk("HeapCreate", 44, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size_arg = regs[1];
        static uint32_t next_heap = 0x01000000;
        mem.Alloc(next_heap, size_arg);
        regs[0] = next_heap;
        next_heap += (size_arg + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("HeapFree", 49, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });
    thunk_handlers["HeapDestroy"] = thunk_handlers["HeapFree"];
    Thunk("HeapReAlloc", 47, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[2], new_size = regs[3];
        static uint32_t next_hrealloc = 0x01100000;
        uint8_t* old_host = mem.Translate(old_ptr);
        uint8_t* new_host = mem.Alloc(next_hrealloc, new_size);
        if (old_host && new_host) memcpy(new_host, old_host, new_size);
        regs[0] = next_hrealloc;
        next_hrealloc += (new_size + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("HeapSize", 48, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x1000; return true;
    });
    Thunk("HeapValidate", 51, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });
    Thunk("malloc", 1041, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size = regs[0];
        static uint32_t next_malloc = 0x01200000;
        mem.Alloc(next_malloc, size > 0 ? size : 0x10);
        regs[0] = next_malloc;
        next_malloc += ((size > 0 ? size : 0x10) + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("calloc", 1346, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size = regs[0] * regs[1];
        static uint32_t next_malloc = 0x01200000;
        mem.Alloc(next_malloc, size > 0 ? size : 0x10);
        uint8_t* p = mem.Translate(next_malloc);
        if (p) memset(p, 0, size);
        regs[0] = next_malloc;
        next_malloc += ((size > 0 ? size : 0x10) + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("new", 1095, thunk_handlers["malloc"]);
    Thunk("realloc", 1054, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[0], size = regs[1];
        static uint32_t next_malloc = 0x01200000;
        uint32_t alloc_size = size > 0 ? size : 0x10;
        uint8_t* new_host = mem.Alloc(next_malloc, alloc_size);
        uint8_t* old_host = old_ptr ? mem.Translate(old_ptr) : nullptr;
        if (old_host && new_host) memcpy(new_host, old_host, std::min(size, (uint32_t)0x1000));
        regs[0] = next_malloc;
        next_malloc += (alloc_size + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("free", 1018, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });
    Thunk("delete", 1094, thunk_handlers["free"]);
    Thunk("_msize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x1000; return true;
    });
}

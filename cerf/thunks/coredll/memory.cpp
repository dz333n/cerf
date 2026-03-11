/* Memory allocation thunks: VirtualAlloc, Heap*, Local*, malloc/free */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <atomic>

/* All allocator bases MUST be below 0x02000000 (32MB slot boundary).
   WinCE ARM code applies slot masking (AND addr, #0x01FFFFFF) to pointers.
   Any address >= 0x02000000 gets corrupted to a different address.
   Address space layout (non-overlapping ranges):
     VirtualAlloc:  0x00200000  (grows up, ~6MB for app VirtualAlloc calls)
     LocalAlloc:    0x00800000  (grows up, ~2MB for small heap allocations)
     LocalReAlloc:  0x00A00000  (grows up, ~2MB for reallocation buffers)
     HeapAlloc:     0x00C00000  (grows up, ~3MB for heap blocks)
     Stack:         0x00F00000-0x01000000  (1MB, grows down from STACK_BASE)
     HeapReAlloc:   0x01000000  (grows up, ~1MB for heap realloc)
     malloc etc:    0x01100000  (grows up, remaining space to 0x02000000)
   Sub-page allocation: blocks <= 4032 bytes use 16-byte alignment within
   shared pages, giving ~50x address space savings for small allocations.
   IMPORTANT: 0x00400000 is NOT available — occupied by system on x64 Windows. */

/* Commit pages covering [addr, addr+size). Skips already-committed pages.
   When a ProcessSlot overlay is active, check the slot's own bitmap rather than
   global memory — otherwise parent process pages shadow the commit check. */
static void CommitPages(EmulatedMemory& mem, uint32_t addr, uint32_t size) {
    for (uint32_t p = addr & ~0xFFFu; p < addr + size; p += 0x1000) {
        if (EmulatedMemory::process_slot && p < ProcessSlot::SLOT_SIZE) {
            if (!EmulatedMemory::process_slot->IsPageCommitted(p))
                mem.Alloc(p, 0x1000);
        } else {
            if (!mem.IsValid(p)) mem.Alloc(p, 0x1000);
        }
    }
}

/* Bump-allocate with sub-page packing for small allocations. */
static uint32_t BumpAlloc(std::atomic<uint32_t>& counter, EmulatedMemory& mem,
                          uint32_t size) {
    uint32_t alloc_size = size > 0 ? size : 0x10;
    /* Small: 16-byte aligned (pack into shared pages). Large: page-aligned. */
    uint32_t step = (alloc_size <= 0xFC0)
        ? std::max((alloc_size + 0xFu) & ~0xFu, 0x10u)
        : std::max((alloc_size + 0xFFFu) & ~0xFFFu, 0x1000u);
    uint32_t addr = counter.fetch_add(step);
    CommitPages(mem, addr, step);
    return addr;
}

void Win32Thunks::RegisterMemoryHandlers() {
    /* Pre-reserve address ranges for each allocator so that page-by-page
       commits within these ranges succeed (Windows requires 64KB-aligned
       addresses for MEM_RESERVE, but MEM_COMMIT works within reservations). */
    mem.Reserve(0x00200000, 0x00600000); /* VirtualAlloc: 0x00200000-0x007FFFFF (6MB) */
    mem.Reserve(0x00800000, 0x00200000); /* LocalAlloc:   0x00800000-0x009FFFFF (2MB) */
    mem.Reserve(0x00A00000, 0x00200000); /* LocalReAlloc: 0x00A00000-0x00BFFFFF (2MB) */
    mem.Reserve(0x00C00000, 0x00300000); /* HeapAlloc:    0x00C00000-0x00EFFFFF (3MB) */
    /* Stack at 0x00F00000-0x01000000 is reserved by AllocStack() */
    mem.Reserve(0x01000000, 0x00100000); /* HeapReAlloc:  0x01000000-0x010FFFFF (1MB) */
    mem.Reserve(0x01100000, 0x00F00000); /* malloc etc:   0x01100000-0x01FFFFFF (15MB) */
    mem.Reserve(0x3F000000, 0x00010000); /* Marshaling scratch buffers (callbacks/dlgproc) */

    Thunk("VirtualAlloc", 524, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr_arg = regs[0], size = regs[1];
        static std::atomic<uint32_t> next_valloc{0x00200000};
        uint32_t aligned = std::max((size + 0xFFF) & ~0xFFF, 0x1000u);
        uint32_t base = addr_arg ? addr_arg : next_valloc.fetch_add(aligned);
        uint8_t* ptr = mem.Alloc(base, size, regs[3]);
        regs[0] = ptr ? base : 0;
        LOG(API, "[API] VirtualAlloc(0x%08X, 0x%X) -> 0x%08X\n", addr_arg, size, regs[0]);
        return true;
    });
    Thunk("VirtualFree", 525, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[STUB] VirtualFree(0x%08X) -> 1 (leak)\n", regs[0]);
        regs[0] = 1; return true;
    });
    Thunk("LocalAlloc", 33, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        static std::atomic<uint32_t> next_local{0x00800000};
        uint32_t addr = BumpAlloc(next_local, mem, regs[1]);
        regs[0] = addr;
        return true;
    });
    thunk_handlers["LocalAllocTrace"] = thunk_handlers["LocalAlloc"];
    Thunk("LocalReAlloc", 34, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[0], new_size = regs[1];
        static std::atomic<uint32_t> next_lrealloc{0x00A00000};
        uint32_t addr = BumpAlloc(next_lrealloc, mem, new_size);
        uint8_t* old_host = mem.Translate(old_ptr);
        uint8_t* new_host = mem.Translate(addr);
        if (old_host && new_host) memcpy(new_host, old_host, new_size);
        regs[0] = addr;
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
        static std::atomic<uint32_t> next_heap{0x00C00000};
        regs[0] = BumpAlloc(next_heap, mem, regs[2]);
        return true;
    };
    Thunk("HeapAlloc", 46, heapAllocImpl);
    Thunk("HeapAllocTrace", 20, heapAllocImpl);
    Thunk("HeapCreate", 44, [](uint32_t* regs, EmulatedMemory&) -> bool {
        static std::atomic<uint32_t> next_handle{0xDEAD0002};
        regs[0] = next_handle.fetch_add(1);
        return true;
    });
    Thunk("HeapFree", 49, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });
    thunk_handlers["HeapDestroy"] = thunk_handlers["HeapFree"];
    Thunk("HeapReAlloc", 47, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[2], new_size = regs[3];
        static std::atomic<uint32_t> next_hrealloc{0x01000000};
        uint32_t addr = BumpAlloc(next_hrealloc, mem, new_size);
        uint8_t* old_host = mem.Translate(old_ptr);
        uint8_t* new_host = mem.Translate(addr);
        if (old_host && new_host) memcpy(new_host, old_host, new_size);
        regs[0] = addr;
        return true;
    });
    Thunk("HeapSize", 48, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x1000; return true;
    });
    Thunk("HeapValidate", 51, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });
    /* Shared atomic counter for malloc/calloc/realloc/new to prevent overlap */
    static std::atomic<uint32_t> next_malloc{0x01100000};
    Thunk("malloc", 1041, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = BumpAlloc(next_malloc, mem, regs[0]);
        return true;
    });
    Thunk("calloc", 1346, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size = regs[0] * regs[1];
        regs[0] = BumpAlloc(next_malloc, mem, size);
        return true;
    });
    Thunk("new", 1095, thunk_handlers["malloc"]);
    Thunk("realloc", 1054, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[0], size = regs[1];
        uint32_t addr = BumpAlloc(next_malloc, mem, size);
        uint8_t* old_host = old_ptr ? mem.Translate(old_ptr) : nullptr;
        uint8_t* new_host = mem.Translate(addr);
        if (old_host && new_host) memcpy(new_host, old_host, size);
        regs[0] = addr;
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

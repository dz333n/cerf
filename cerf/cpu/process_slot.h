#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>

/* Per-process virtual address space overlay (WinCE slot 0: 0x00000000-0x01FFFFFF).
   Each WinCE process gets its own 32MB slot. When a child process runs on a thread,
   that thread's process_slot pointer is set so Translate() returns the overlay's
   memory instead of the parent's for addresses in [0, SLOT_SIZE). DLLs above
   0x02000000 are shared and not overlaid.

   IMPORTANT: Only pages explicitly committed via Commit() are intercepted by
   Translate(). Other slot 0 addresses fall through to global memory. This prevents
   the child process from shadowing the parent's heap allocations (e.g. ole32.dll's
   CDllCache stores heap pointers in slot 0 range that must resolve to the parent's
   data, not the child's empty overlay). */
struct ProcessSlot {
    static const uint32_t SLOT_SIZE = 0x02000000; /* 32 MB */
    static const uint32_t IDENTITY_BASE = 0x00010000; /* WinCE EXE base */
    static const uint32_t PAGE_SIZE = 0x1000;
    static const uint32_t NUM_PAGES = SLOT_SIZE / PAGE_SIZE; /* 8192 pages */
    uint8_t* buffer = nullptr;    /* Host allocation backing the slot */
    uint32_t committed = 0;       /* Bytes actually committed (may be < SLOT_SIZE) */
    bool identity_mapped = false; /* True if ARM addresses == native addresses */
    uint32_t image_base = 0;     /* Start of loaded PE image */
    uint32_t image_end = 0;      /* End of loaded PE image (base + size_of_image) */
    uint8_t page_bitmap[NUM_PAGES / 8] = {}; /* 1 bit per page: committed or not */

    ProcessSlot() {
        /* Try identity-mapped allocation: reserve native addresses 0x00010000-0x01FFFFFF
           so ARM pointers passed to native controls (SysListView32 etc.) work as-is. */
        void* p = VirtualAlloc((void*)(uintptr_t)IDENTITY_BASE,
                               SLOT_SIZE - IDENTITY_BASE,
                               MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (p == (void*)(uintptr_t)IDENTITY_BASE) {
            buffer = (uint8_t*)p;
            identity_mapped = true;
        } else {
            if (p) VirtualFree(p, 0, MEM_RELEASE);
            buffer = (uint8_t*)VirtualAlloc(NULL, SLOT_SIZE,
                                             MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        }
        memset(page_bitmap, 0, sizeof(page_bitmap));
    }
    ~ProcessSlot() {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
    }

    void MarkPages(uint32_t offset, uint32_t size) {
        uint32_t first = offset / PAGE_SIZE;
        uint32_t last = (offset + size - 1) / PAGE_SIZE;
        for (uint32_t p = first; p <= last && p < NUM_PAGES; p++)
            page_bitmap[p / 8] |= (1u << (p & 7));
    }

    bool IsPageCommitted(uint32_t addr) const {
        uint32_t p = addr / PAGE_SIZE;
        if (p >= NUM_PAGES) return false;
        return (page_bitmap[p / 8] & (1u << (p & 7))) != 0;
    }

    /* Commit pages within the slot (relative to slot base 0) */
    bool Commit(uint32_t offset, uint32_t size) {
        if (identity_mapped) {
            /* Identity: only addresses >= IDENTITY_BASE are backed */
            if (offset < IDENTITY_BASE) {
                if (offset + size <= IDENTITY_BASE) return true;
                size -= (IDENTITY_BASE - offset);
                offset = IDENTITY_BASE;
            }
            if (offset + size > SLOT_SIZE) return false;
            MarkPages(offset, size);
            return true;
        }
        if (!buffer || offset + size > SLOT_SIZE) return false;
        uint32_t page_off = offset & ~0xFFFu;
        uint32_t page_end = (offset + size + 0xFFF) & ~0xFFFu;
        void* p = VirtualAlloc(buffer + page_off, page_end - page_off,
                               MEM_COMMIT, PAGE_READWRITE);
        if (p) MarkPages(page_off, page_end - page_off);
        return p != nullptr;
    }

    /* Translate an ARM address within slot range to host pointer.
       Only returns non-null for pages that were explicitly committed. */
    uint8_t* Translate(uint32_t addr) const {
        if (addr >= SLOT_SIZE) return nullptr;
        if (!IsPageCommitted(addr)) return nullptr;
        if (identity_mapped) {
            if (addr < IDENTITY_BASE) return nullptr;
            return (uint8_t*)(uintptr_t)addr;
        }
        if (!buffer) return nullptr;
        return buffer + addr;
    }
};

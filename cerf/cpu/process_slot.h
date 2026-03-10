#pragma once
#include <windows.h>
#include <cstdint>

/* Per-process virtual address space overlay (WinCE slot 0: 0x00000000-0x01FFFFFF).
   Each WinCE process gets its own 32MB slot. When a child process runs on a thread,
   that thread's process_slot pointer is set so Translate() returns the overlay's
   memory instead of the parent's for addresses in [0, SLOT_SIZE). DLLs above
   0x02000000 are shared and not overlaid. */
struct ProcessSlot {
    static const uint32_t SLOT_SIZE = 0x02000000; /* 32 MB */
    static const uint32_t IDENTITY_BASE = 0x00010000; /* WinCE EXE base */
    uint8_t* buffer = nullptr;    /* Host allocation backing the slot */
    uint32_t committed = 0;       /* Bytes actually committed (may be < SLOT_SIZE) */
    bool identity_mapped = false; /* True if ARM addresses == native addresses */

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
    }
    ~ProcessSlot() {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
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
            return offset + size <= SLOT_SIZE;
        }
        if (!buffer || offset + size > SLOT_SIZE) return false;
        uint32_t page_off = offset & ~0xFFFu;
        uint32_t page_end = (offset + size + 0xFFF) & ~0xFFFu;
        void* p = VirtualAlloc(buffer + page_off, page_end - page_off,
                               MEM_COMMIT, PAGE_READWRITE);
        return p != nullptr;
    }

    /* Translate an ARM address within slot range to host pointer */
    uint8_t* Translate(uint32_t addr) const {
        if (identity_mapped) {
            if (addr < IDENTITY_BASE || addr >= SLOT_SIZE) return nullptr;
            return (uint8_t*)(uintptr_t)addr;
        }
        if (!buffer || addr >= SLOT_SIZE) return nullptr;
        return buffer + addr;
    }
};

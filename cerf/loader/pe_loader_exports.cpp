#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* PE DLL loading, ProcessSlot loading, export resolution — split from pe_loader.cpp */
#include "pe_loader.h"
#include "../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

static bool IsRegionFree(EmulatedMemory& mem, uint32_t base, uint32_t size) {
    for (auto& r : mem.regions) {
        if (base < r.base + r.size && base + size > r.base) return false;
    }
    return true;
}

static uint32_t FindFreeBase(EmulatedMemory& mem, uint32_t preferred, uint32_t size) {
    if (IsRegionFree(mem, preferred, size)) return preferred;
    uint32_t aligned_size = (size + 0xFFFF) & ~0xFFFF;
    for (uint32_t base = preferred + aligned_size; base < 0x70000000; base += 0x10000) {
        base = (base + 0xFFFF) & ~0xFFFF;
        if (IsRegionFree(mem, base, size)) return base;
    }
    return 0;
}

uint32_t PELoader::LoadDll(const char* path, EmulatedMemory& mem, PEInfo& info) {
    FILE* f = fopen(path, "rb");
    if (!f) { LOG_ERR("[PE] Cannot open: %s\n", path); return 0; }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> data(size);
    fread(data.data(), 1, size, f);
    fclose(f);

    LOG(PE, "[PE] Loading DLL %s (%zu bytes)\n", path, size);
    if (!ParseHeaders(data.data(), size, info)) return 0;

    uint32_t original_base = info.image_base;
    uint32_t actual_base = FindFreeBase(mem, info.image_base, info.size_of_image);
    if (actual_base == 0) { LOG_ERR("[PE] Cannot find free base for DLL %s\n", path); return 0; }
    if (actual_base != original_base) {
        LOG(PE, "[PE] Relocating DLL from 0x%08X to 0x%08X\n", original_base, actual_base);
        info.image_base = actual_base;
    }
    if (!LoadSections(data.data(), size, mem, info)) return 0;

    if (actual_base != original_base) {
        if (info.reloc_rva == 0 || info.reloc_size == 0) {
            LOG_ERR("[PE] DLL needs relocation but has no .reloc section!\n");
            return 0;
        }
        int32_t delta = (int32_t)actual_base - (int32_t)original_base;
        uint32_t offset = 0;
        while (offset < info.reloc_size) {
            uint32_t block_rva = mem.Read32(actual_base + info.reloc_rva + offset);
            uint32_t block_size = mem.Read32(actual_base + info.reloc_rva + offset + 4);
            if (block_size == 0) break;
            uint32_t num_entries = (block_size - 8) / 2;
            for (uint32_t i = 0; i < num_entries; i++) {
                uint16_t entry = mem.Read16(actual_base + info.reloc_rva + offset + 8 + i * 2);
                uint16_t type = entry >> 12;
                uint16_t off = entry & 0xFFF;
                if (type == IMAGE_REL_BASED_HIGHLOW || type == 3) {
                    uint32_t addr = actual_base + block_rva + off;
                    mem.Write32(addr, mem.Read32(addr) + delta);
                }
            }
            offset += block_size;
        }
        LOG(PE, "[PE] DLL relocated with delta=0x%X\n", delta);
    }
    if (!ResolveImports(data.data(), size, mem, info)) return 0;

    uint32_t entry = info.image_base + info.entry_point_rva;
    LOG(PE, "[PE] DLL entry point: 0x%08X\n", entry);
    return entry;
}

uint32_t PELoader::LoadIntoSlot(const char* path, EmulatedMemory& mem,
                                PEInfo& info, ProcessSlot& slot) {
    FILE* f = fopen(path, "rb");
    if (!f) { LOG_ERR("[PE] Cannot open: %s\n", path); return 0; }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> data(size);
    fread(data.data(), 1, size, f);
    fclose(f);

    LOG(PE, "[PE] Loading into ProcessSlot: %s (%zu bytes)\n", path, size);
    if (!ParseHeaders(data.data(), size, info)) return 0;

    /* Verify the image fits within slot 0 (0x00000000-0x01FFFFFF) */
    if (info.image_base + info.size_of_image > ProcessSlot::SLOT_SIZE) {
        LOG_ERR("[PE] Image 0x%08X+0x%X exceeds slot 0 boundary\n",
                info.image_base, info.size_of_image);
        return 0;
    }

    /* Record the image range so Translate only overlays PE addresses */
    slot.image_base = info.image_base;
    slot.image_end = info.image_base + info.size_of_image;

    /* Commit pages in the slot for the image */
    if (!slot.Commit(info.image_base, info.size_of_image)) {
        LOG_ERR("[PE] Failed to commit slot pages for 0x%08X+0x%X\n",
                info.image_base, info.size_of_image);
        return 0;
    }

    /* Copy headers into slot buffer — use Translate for identity-mapped slots */
    uint8_t* image = slot.Translate(info.image_base);
    if (!image) {
        LOG_ERR("[PE] Cannot translate image base 0x%08X in slot\n", info.image_base);
        return 0;
    }
    uint32_t hdr_copy = std::min((uint32_t)size, info.size_of_headers);
    memcpy(image, data.data(), hdr_copy);

    /* Copy sections into slot buffer */
    for (auto& s : info.sections) {
        if (s.PointerToRawData == 0) continue;
        DWORD raw_size = s.SizeOfRawData;
        if (raw_size == 0) raw_size = s.Misc.VirtualSize;
        if (raw_size == 0) continue;
        if (s.PointerToRawData + raw_size > size) continue;
        DWORD vsize = s.Misc.VirtualSize ? s.Misc.VirtualSize : raw_size;
        uint32_t copy_size = (raw_size < vsize) ? raw_size : vsize;
        uint8_t* section_dst = slot.Translate(info.image_base + s.VirtualAddress);
        if (section_dst)
            memcpy(section_dst, data.data() + s.PointerToRawData, copy_size);
    }

    /* No relocation needed — image loads at its preferred base within the slot */

    /* Activate the slot overlay for this thread so ResolveImports can read
       the import tables from the slot via mem.Translate() */
    ProcessSlot* prev_slot = EmulatedMemory::process_slot;
    EmulatedMemory::process_slot = &slot;

    if (!ResolveImports(data.data(), size, mem, info)) {
        EmulatedMemory::process_slot = prev_slot;
        return 0;
    }

    /* Commit stack area in the slot (0x00FF0000-0x00FFFFFF = 64KB for the child) */
    slot.Commit(0x00FF0000, 0x10000);

    uint32_t entry = info.image_base + info.entry_point_rva;
    LOG(PE, "[PE] ProcessSlot entry point: 0x%08X\n", entry);
    /* Leave process_slot active — caller manages lifetime */
    EmulatedMemory::process_slot = prev_slot;
    return entry;
}

uint32_t PELoader::ResolveExportOrdinal(EmulatedMemory& mem, const PEInfo& info, uint16_t ordinal) {
    if (info.export_rva == 0 || info.export_size == 0) return 0;

    uint32_t base = info.image_base;
    uint32_t export_dir = base + info.export_rva;

    uint32_t ordinal_base = mem.Read32(export_dir + 0x10);
    uint32_t num_functions = mem.Read32(export_dir + 0x14);
    uint32_t addr_of_functions = base + mem.Read32(export_dir + 0x1C);

    uint32_t index = ordinal - ordinal_base;
    if (index >= num_functions) {
        LOG(PE, "[PE] Export ordinal %d out of range (base=%d, count=%d)\n",
               ordinal, ordinal_base, num_functions);
        return 0;
    }

    uint32_t func_rva = mem.Read32(addr_of_functions + index * 4);
    if (func_rva == 0) return 0;

    /* Check for forwarded export (RVA points within export directory) */
    if (func_rva >= info.export_rva && func_rva < info.export_rva + info.export_size) {
        uint8_t* fwd = mem.Translate(base + func_rva);
        if (fwd) {
            LOG(PE, "[PE] Export ordinal %d is forwarded to: %s\n", ordinal, (char*)fwd);
        }
        return 0;
    }

    uint32_t addr = base + func_rva;
    LOG(PE, "[PE] Resolved export ordinal %d -> 0x%08X (RVA=0x%08X)\n", ordinal, addr, func_rva);
    return addr;
}

uint32_t PELoader::ResolveExportName(EmulatedMemory& mem, const PEInfo& info, const std::string& name) {
    if (info.export_rva == 0 || info.export_size == 0) return 0;

    uint32_t base = info.image_base;
    uint32_t export_dir = base + info.export_rva;

    uint32_t ordinal_base = mem.Read32(export_dir + 0x10);
    uint32_t num_functions = mem.Read32(export_dir + 0x14);
    uint32_t num_names = mem.Read32(export_dir + 0x18);
    uint32_t addr_of_functions = base + mem.Read32(export_dir + 0x1C);
    uint32_t addr_of_names = base + mem.Read32(export_dir + 0x20);
    uint32_t addr_of_ordinals = base + mem.Read32(export_dir + 0x24);

    for (uint32_t i = 0; i < num_names; i++) {
        uint32_t name_rva = mem.Read32(addr_of_names + i * 4);
        uint8_t* name_ptr = mem.Translate(base + name_rva);
        if (name_ptr && strcmp((char*)name_ptr, name.c_str()) == 0) {
            uint16_t ordinal_index = mem.Read16(addr_of_ordinals + i * 2);
            if (ordinal_index >= num_functions) return 0;
            uint32_t func_rva = mem.Read32(addr_of_functions + ordinal_index * 4);
            if (func_rva == 0) return 0;
            uint32_t addr = base + func_rva;
            LOG(PE, "[PE] Resolved export '%s' -> 0x%08X\n", name.c_str(), addr);
            return addr;
        }
    }
    return 0;
}

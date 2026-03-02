#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdarg>

namespace Log {

    enum Category : uint32_t {
        NONE   = 0,
        THUNK  = 1 << 0,
        PE     = 1 << 1,
        EMU    = 1 << 2,
        TRACE  = 1 << 3,
        CPU    = 1 << 4,
        REG    = 1 << 5,
        DBG    = 1 << 6,
        VFS    = 1 << 7,
        ALL    = 0xFFFFFFFF
    };

    void Init();
    void SetEnabled(uint32_t mask);
    uint32_t GetEnabled();
    void EnableCategory(Category cat);
    void DisableCategory(Category cat);
    void SetFile(const char* path);
    void SetFlush(bool enabled);
    void Close();

    void Print(Category cat, const char* fmt, ...);
    void Err(const char* fmt, ...);
    void Raw(const char* fmt, ...);

    inline bool IsEnabled(Category cat) { return (GetEnabled() & cat) != 0; }

    /* Parse a comma-separated category string like "THUNK,PE,EMU" into a bitmask.
       Special values: "all", "none". Case-insensitive. */
    uint32_t ParseCategories(const char* str);
}

/* Convenience macros — check bitmask before formatting for near-zero cost when disabled */
#define LOG(cat, ...) do { if (Log::IsEnabled(Log::cat)) Log::Print(Log::cat, __VA_ARGS__); } while(0)
#define LOG_ERR(...) Log::Err(__VA_ARGS__)
#define LOG_RAW(...) Log::Raw(__VA_ARGS__)

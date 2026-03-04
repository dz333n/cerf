#include "log.h"
#include <cstring>
#include <cctype>
#include <string>
#include <algorithm>

static uint32_t g_enabled = Log::ALL & ~Log::TRACE;
static FILE* g_logfile = nullptr;
static bool g_flush = false;

void Log::Init() {
    g_enabled = ALL & ~TRACE;
    g_logfile = nullptr;
    g_flush = false;
}

void Log::SetEnabled(uint32_t mask) {
    g_enabled = mask;
}

uint32_t Log::GetEnabled() {
    return g_enabled;
}

void Log::EnableCategory(Category cat) {
    g_enabled |= cat;
}

void Log::DisableCategory(Category cat) {
    g_enabled &= ~cat;
}

void Log::SetFile(const char* path) {
    if (g_logfile) {
        fclose(g_logfile);
        g_logfile = nullptr;
    }
    g_logfile = fopen(path, "w");
    if (!g_logfile) {
        fprintf(stderr, "Warning: could not open log file '%s'\n", path);
    }
}

void Log::SetFlush(bool enabled) {
    g_flush = enabled;
}

void Log::Close() {
    if (g_logfile) {
        fflush(g_logfile);
        fclose(g_logfile);
        g_logfile = nullptr;
    }
}

void Log::Print(Category cat, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (g_enabled & cat) {
        vprintf(fmt, args);
        if (g_flush) fflush(stdout);
    }
    if (g_logfile) {
        va_list args2;
        va_copy(args2, args);
        vfprintf(g_logfile, fmt, args2);
        va_end(args2);
        if (g_flush) fflush(g_logfile);
    }
    va_end(args);
}

void Log::Err(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    if (g_logfile) {
        va_list args2;
        va_copy(args2, args);
        vfprintf(g_logfile, fmt, args2);
        va_end(args2);
        if (g_flush) fflush(g_logfile);
    }
    va_end(args);
}

void Log::Raw(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    if (g_flush) fflush(stdout);
    if (g_logfile) {
        va_list args2;
        va_copy(args2, args);
        vfprintf(g_logfile, fmt, args2);
        va_end(args2);
        if (g_flush) fflush(g_logfile);
    }
    va_end(args);
}

uint32_t Log::ParseCategories(const char* str) {
    std::string s(str);
    /* Convert to uppercase */
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);

    if (s == "ALL") return ALL;
    if (s == "NONE") return NONE;

    uint32_t mask = 0;
    size_t start = 0;
    while (start < s.size()) {
        size_t end = s.find(',', start);
        if (end == std::string::npos) end = s.size();
        std::string token = s.substr(start, end - start);

        if (token == "API")        mask |= API;
        else if (token == "PE")    mask |= PE;
        else if (token == "EMU")   mask |= EMU;
        else if (token == "TRACE") mask |= TRACE;
        else if (token == "CPU")   mask |= CPU;
        else if (token == "REG")   mask |= REG;
        else if (token == "DBG" || token == "DEBUG") mask |= DBG;
        else if (token == "VFS")   mask |= VFS;
        else fprintf(stderr, "Warning: unknown log category '%s'\n", token.c_str());

        start = end + 1;
    }
    return mask;
}

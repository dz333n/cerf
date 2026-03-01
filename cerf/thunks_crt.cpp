/* CRT thunks: memcpy, memset, qsort, rand, math */
#include "win32_thunks.h"
#include <cstdio>
#include <cstring>
#include <cmath>

void Win32Thunks::RegisterCrtHandlers() {
    Thunk("memcpy", 1044, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], len = regs[2];
        uint8_t* dst_p = mem.Translate(dst);
        uint8_t* src_p = mem.Translate(src);
        if (dst_p && src_p) memcpy(dst_p, src_p, len);
        regs[0] = dst; return true;
    });
    Thunk("memmove", 1046, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], len = regs[2];
        uint8_t* dst_p = mem.Translate(dst);
        uint8_t* src_p = mem.Translate(src);
        if (dst_p && src_p) memmove(dst_p, src_p, len);
        regs[0] = dst; return true;
    });
    Thunk("memset", 1047, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint8_t* p = mem.Translate(regs[0]);
        if (p) memset(p, (uint8_t)regs[1], regs[2]);
        regs[0] = regs[0]; return true;
    });
    Thunk("memcmp", 1043, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint8_t* ap = mem.Translate(regs[0]);
        uint8_t* bp = mem.Translate(regs[1]);
        regs[0] = (ap && bp) ? (uint32_t)memcmp(ap, bp, regs[2]) : 0;
        return true;
    });
    Thunk("_memicmp", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint8_t* ap = mem.Translate(regs[0]);
        uint8_t* bp = mem.Translate(regs[1]);
        regs[0] = (ap && bp) ? (uint32_t)_memicmp(ap, bp, regs[2]) : 0;
        return true;
    });
    Thunk("qsort", 1052, [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] WARNING: qsort called - stubbed\n"); return true;
    });
    Thunk("rand", 1053, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)rand(); return true;
    });
    Thunk("Random", 80, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(rand() % 0xFFFF); return true;
    });
    Thunk("srand", 1061, [](uint32_t* regs, EmulatedMemory&) -> bool {
        srand(regs[0]); return true;
    });
    Thunk("pow", 1051, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t ba = ((uint64_t)regs[1] << 32) | regs[0];
        uint64_t bb = ((uint64_t)regs[3] << 32) | regs[2];
        double a, b; memcpy(&a, &ba, 8); memcpy(&b, &bb, 8);
        double r = pow(a, b); uint64_t rb; memcpy(&rb, &r, 8);
        regs[0] = (uint32_t)rb; regs[1] = (uint32_t)(rb >> 32);
        return true;
    });
    Thunk("sqrt", 1060, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t bits = ((uint64_t)regs[1] << 32) | regs[0];
        double d; memcpy(&d, &bits, 8); d = sqrt(d); memcpy(&bits, &d, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        return true;
    });
    Thunk("floor", 1013, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t bits = ((uint64_t)regs[1] << 32) | regs[0];
        double d; memcpy(&d, &bits, 8); d = floor(d); memcpy(&bits, &d, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        return true;
    });
}

/* ARM compiler runtime: integer division, 64-bit shifts, soft-float helpers */
#include "win32_thunks.h"
#include <cstring>

void Win32Thunks::RegisterArmRuntimeHandlers() {
    /* Helper lambdas for float/double <-> register conversion */
    auto regs_to_double = [](uint32_t lo, uint32_t hi) -> double {
        uint64_t bits = ((uint64_t)hi << 32) | lo;
        double d; memcpy(&d, &bits, sizeof(d)); return d;
    };
    auto double_to_regs = [](double d, uint32_t* r) {
        uint64_t bits; memcpy(&bits, &d, sizeof(bits));
        r[0] = (uint32_t)bits; r[1] = (uint32_t)(bits >> 32);
    };
    auto regs_to_float = [](uint32_t r) -> float {
        float f; memcpy(&f, &r, sizeof(f)); return f;
    };
    auto float_to_reg = [](float f) -> uint32_t {
        uint32_t r; memcpy(&r, &f, sizeof(r)); return r;
    };

    /* Signed division: R0=divisor, R1=dividend -> R0=quotient, R1=remainder */
    Thunk("__rt_sdiv", 2005, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int32_t divisor = (int32_t)regs[0], dividend = (int32_t)regs[1];
        if (divisor == 0) { regs[0] = 0; regs[1] = 0; return true; }
        regs[0] = (uint32_t)(dividend / divisor);
        regs[1] = (uint32_t)(dividend % divisor);
        return true;
    });
    Thunk("__rt_udiv", 2008, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t divisor = regs[0], dividend = regs[1];
        if (divisor == 0) { regs[0] = 0; regs[1] = 0; return true; }
        regs[0] = dividend / divisor; regs[1] = dividend % divisor;
        return true;
    });
    Thunk("__rt_sdiv10", 2006, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int32_t val = (int32_t)regs[0];
        regs[0] = (uint32_t)(val / 10); regs[1] = (uint32_t)(val % 10);
        return true;
    });
    Thunk("__rt_udiv10", 2009, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t val = regs[0];
        regs[0] = val / 10; regs[1] = val % 10;
        return true;
    });
    Thunk("__rt_sdiv64by64", 2000, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int64_t dividend = (int64_t)(((uint64_t)regs[1] << 32) | regs[0]);
        int64_t divisor = (int64_t)(((uint64_t)regs[3] << 32) | regs[2]);
        if (divisor == 0) { regs[0] = 0; regs[1] = 0; return true; }
        int64_t q = dividend / divisor;
        regs[0] = (uint32_t)q; regs[1] = (uint32_t)(q >> 32);
        return true;
    });
    Thunk("__rt_srem64by64", 2001, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int64_t dividend = (int64_t)(((uint64_t)regs[1] << 32) | regs[0]);
        int64_t divisor = (int64_t)(((uint64_t)regs[3] << 32) | regs[2]);
        if (divisor == 0) { regs[0] = 0; regs[1] = 0; return true; }
        int64_t r = dividend % divisor;
        regs[0] = (uint32_t)r; regs[1] = (uint32_t)(r >> 32);
        return true;
    });
    Thunk("__rt_udiv64by64", 2002, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t dividend = ((uint64_t)regs[1] << 32) | regs[0];
        uint64_t divisor = ((uint64_t)regs[3] << 32) | regs[2];
        if (divisor == 0) { regs[0] = 0; regs[1] = 0; return true; }
        uint64_t q = dividend / divisor;
        regs[0] = (uint32_t)q; regs[1] = (uint32_t)(q >> 32);
        return true;
    });
    Thunk("__rt_urem64by64", 2003, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t dividend = ((uint64_t)regs[1] << 32) | regs[0];
        uint64_t divisor = ((uint64_t)regs[3] << 32) | regs[2];
        if (divisor == 0) { regs[0] = 0; regs[1] = 0; return true; }
        uint64_t r = dividend % divisor;
        regs[0] = (uint32_t)r; regs[1] = (uint32_t)(r >> 32);
        return true;
    });
    Thunk("__rt_srsh", 2010, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int64_t val = (int64_t)(((uint64_t)regs[1] << 32) | regs[0]);
        val >>= (regs[2] & 63);
        regs[0] = (uint32_t)val; regs[1] = (uint32_t)(val >> 32);
        return true;
    });
    Thunk("__rt_ursh", 2011, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t val = ((uint64_t)regs[1] << 32) | regs[0];
        val >>= (regs[2] & 63);
        regs[0] = (uint32_t)val; regs[1] = (uint32_t)(val >> 32);
        return true;
    });

    /* Double arithmetic */
    Thunk("__addd", 2053, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        double_to_regs(regs_to_double(regs[0],regs[1]) + regs_to_double(regs[2],regs[3]), regs); return true;
    });
    Thunk("__subd", 2016, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        double_to_regs(regs_to_double(regs[0],regs[1]) - regs_to_double(regs[2],regs[3]), regs); return true;
    });
    Thunk("__muld", 2027, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        double_to_regs(regs_to_double(regs[0],regs[1]) * regs_to_double(regs[2],regs[3]), regs); return true;
    });
    Thunk("__divd", 2048, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        double b = regs_to_double(regs[2],regs[3]);
        double_to_regs(b != 0.0 ? regs_to_double(regs[0],regs[1]) / b : 0.0, regs); return true;
    });
    Thunk("__negd", 2024, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        double_to_regs(-regs_to_double(regs[0],regs[1]), regs); return true;
    });

    /* Float arithmetic */
    Thunk("__adds", 2051, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = float_to_reg(regs_to_float(regs[0]) + regs_to_float(regs[1])); return true;
    });
    Thunk("__subs", 2015, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = float_to_reg(regs_to_float(regs[0]) - regs_to_float(regs[1])); return true;
    });
    Thunk("__muls", 2026, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = float_to_reg(regs_to_float(regs[0]) * regs_to_float(regs[1])); return true;
    });
    Thunk("__divs", 2047, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        float b = regs_to_float(regs[1]);
        regs[0] = float_to_reg(b != 0.0f ? regs_to_float(regs[0]) / b : 0.0f); return true;
    });
    Thunk("__negs", 2023, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = float_to_reg(-regs_to_float(regs[0])); return true;
    });

    /* Int/uint to double */
    Thunk("__itod", 2033, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        double_to_regs((double)(int32_t)regs[0], regs); return true;
    });
    Thunk("__utod", 2012, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        double_to_regs((double)(uint32_t)regs[0], regs); return true;
    });
    Thunk("__i64tod", 2035, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        int64_t val = (int64_t)(((uint64_t)regs[1] << 32) | regs[0]);
        double_to_regs((double)val, regs); return true;
    });
    Thunk("__u64tod", 2014, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t val = ((uint64_t)regs[1] << 32) | regs[0];
        double_to_regs((double)val, regs); return true;
    });

    /* Int/uint to float */
    Thunk("__itos", 2032, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = float_to_reg((float)(int32_t)regs[0]); return true;
    });
    Thunk("__utos", 2052, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = float_to_reg((float)(uint32_t)regs[0]); return true;
    });
    Thunk("__i64tos", 2034, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        int64_t val = (int64_t)(((uint64_t)regs[1] << 32) | regs[0]);
        regs[0] = float_to_reg((float)val); return true;
    });
    Thunk("__u64tos", 2013, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t val = ((uint64_t)regs[1] << 32) | regs[0];
        regs[0] = float_to_reg((float)val); return true;
    });

    /* Double to int/uint */
    Thunk("__dtoi", 2046, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(int32_t)regs_to_double(regs[0],regs[1]); return true;
    });
    Thunk("__dtou", 2043, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)regs_to_double(regs[0],regs[1]); return true;
    });
    Thunk("__dtoi64", 2045, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        int64_t val = (int64_t)regs_to_double(regs[0],regs[1]);
        regs[0] = (uint32_t)val; regs[1] = (uint32_t)(val >> 32); return true;
    });
    Thunk("__dtou64", 2042, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t val = (uint64_t)regs_to_double(regs[0],regs[1]);
        regs[0] = (uint32_t)val; regs[1] = (uint32_t)(val >> 32); return true;
    });

    /* Float to int/uint */
    Thunk("__stoi", 2020, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(int32_t)regs_to_float(regs[0]); return true;
    });
    Thunk("__stou", 2018, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)regs_to_float(regs[0]); return true;
    });
    Thunk("__stoi64", 2019, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        int64_t val = (int64_t)regs_to_float(regs[0]);
        regs[0] = (uint32_t)val; regs[1] = (uint32_t)(val >> 32); return true;
    });
    Thunk("__stou64", 2017, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t val = (uint64_t)regs_to_float(regs[0]);
        regs[0] = (uint32_t)val; regs[1] = (uint32_t)(val >> 32); return true;
    });

    /* Float <-> double */
    Thunk("__stod", 2021, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        double_to_regs((double)regs_to_float(regs[0]), regs); return true;
    });
    Thunk("__dtos", 2044, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = float_to_reg((float)regs_to_double(regs[0],regs[1])); return true;
    });

    /* Double comparisons */
    Thunk("__cmpd", 2050, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        double a = regs_to_double(regs[0],regs[1]), b = regs_to_double(regs[2],regs[3]);
        regs[0] = (a < b) ? (uint32_t)-1 : (a > b) ? 1 : 0; return true;
    });
    Thunk("__eqd", 2041, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_double(regs[0],regs[1]) == regs_to_double(regs[2],regs[3])) ? 1 : 0; return true;
    });
    Thunk("__ned", 2025, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_double(regs[0],regs[1]) != regs_to_double(regs[2],regs[3])) ? 1 : 0; return true;
    });
    Thunk("__ltd", 2029, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_double(regs[0],regs[1]) < regs_to_double(regs[2],regs[3])) ? 1 : 0; return true;
    });
    Thunk("__led", 2031, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_double(regs[0],regs[1]) <= regs_to_double(regs[2],regs[3])) ? 1 : 0; return true;
    });
    Thunk("__gtd", 2037, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_double(regs[0],regs[1]) > regs_to_double(regs[2],regs[3])) ? 1 : 0; return true;
    });
    Thunk("__ged", 2039, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_double(regs[0],regs[1]) >= regs_to_double(regs[2],regs[3])) ? 1 : 0; return true;
    });

    /* Float comparisons */
    Thunk("__cmps", 2049, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        float a = regs_to_float(regs[0]), b = regs_to_float(regs[1]);
        regs[0] = (a < b) ? (uint32_t)-1 : (a > b) ? 1 : 0; return true;
    });
    Thunk("__eqs", 2040, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_float(regs[0]) == regs_to_float(regs[1])) ? 1 : 0; return true;
    });
    Thunk("__nes", 2022, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_float(regs[0]) != regs_to_float(regs[1])) ? 1 : 0; return true;
    });
    Thunk("__lts", 2028, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_float(regs[0]) < regs_to_float(regs[1])) ? 1 : 0; return true;
    });
    Thunk("__les", 2030, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_float(regs[0]) <= regs_to_float(regs[1])) ? 1 : 0; return true;
    });
    Thunk("__gts", 2036, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_float(regs[0]) > regs_to_float(regs[1])) ? 1 : 0; return true;
    });
    Thunk("__ges", 2038, [=](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (regs_to_float(regs[0]) >= regs_to_float(regs[1])) ? 1 : 0; return true;
    });
}

/* Runtime patches for ARM DLLs loaded into emulated memory.
   These fix known issues in OLE32, RPCRT4, and Explorer binaries. */

#include "patches.h"
#include "cpu/mem.h"
#include "log.h"

void ApplyRuntimePatches(EmulatedMemory& mem) {
    constexpr uint32_t ARM_BX_LR = 0xE12FFF1E;
    constexpr uint32_t ARM_MVN_R0_0 = 0xE3E00000; /* MVN R0,#0 → R0=-1 */

    /* Patch OLE32: AssertValid, GetTreatAs, CDllCache corrupted linked lists */
    if (mem.IsValid(0x100944DC)) {
        mem.Write32(0x100944DC, ARM_BX_LR); /* AssertValid */
        const uint32_t gt[] = { 0xE5902000, 0xE5812000, 0xE5902004, 0xE5812004,
            0xE5902008, 0xE5812008, 0xE590200C, 0xE581200C, 0xE3A00000, ARM_BX_LR };
        for (int i = 0; i < 10; i++) mem.Write32(0x10088DFC + i * 4, gt[i]);
        /* CDllCache: Search* return -1, rest BX LR */
        for (auto a : {0x10065218u,0x10065364u,0x10065440u}) { mem.Write32(a, ARM_MVN_R0_0); mem.Write32(a+4, ARM_BX_LR); }
        for (auto a : {0x10063DB8u,0x10064510u,0x10064628u,0x10064CB8u,0x10064E80u,0x10064FFCu,0x10065B20u,0x10065ED8u}) mem.Write32(a, ARM_BX_LR);
        LOG(EMU, "[EMU] Patched OLE32: AssertValid+GetTreatAs+CDllCache(11 funcs)\n");
    }

    /* RPCRT4 stubs */
    for (auto a : {0x10146464u, 0x101880A0u, 0x10187E78u})
        if (mem.IsValid(a)) mem.Write32(a, ARM_BX_LR);

    /* OLE32 CoMarshalInterThreadInterface: fail cleanly */
    if (mem.IsValid(0x100239FC)) {
        mem.Write32(0x100239FC, 0xE3A03000); mem.Write32(0x10023A00, 0xE5823000);
        mem.Write32(0x10023A04, ARM_MVN_R0_0); mem.Write32(0x10023A08, ARM_BX_LR);
    }

    /* Explorer: skip corrupt _pIPActiveObj block */
    if (mem.IsValid(0x00021EF4))
        mem.Write32(0x00021EF4, 0xEA00001B);
}

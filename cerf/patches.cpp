/* Runtime patches for ARM DLLs loaded into emulated memory.
   IMPORTANT: Hardcoded address-based patches are FORBIDDEN.
   Multiple DLLs can load at overlapping addresses (e.g. commctrl.dll
   and OLE32 both use 0x10000000 base). Address-based patches WILL
   corrupt unrelated DLLs. Fix API deficiencies instead. */

#include "patches.h"
#include "cpu/mem.h"
#include "log.h"

void ApplyRuntimePatches(EmulatedMemory& /* mem */) {
    /* No hardcoded patches. Fix problems at the API thunk level. */
}

#pragma once

class EmulatedMemory;

/* Apply runtime patches to loaded ARM DLLs (OLE32, RPCRT4, Explorer).
   These patch corrupted linked lists, stub out unimplemented COM/RPC
   functions, and skip known-bad code paths in the ARM binaries. */
void ApplyRuntimePatches(EmulatedMemory& mem);

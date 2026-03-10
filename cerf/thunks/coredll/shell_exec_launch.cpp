#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* ARM PE child process launch for ShellExecuteEx — creates a new OS thread
   with its own ProcessSlot, ThreadContext, ArmCpu, and isolated address space. */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>


bool Win32Thunks::LaunchArmChildProcess(
    const std::wstring& mapped_file, const std::wstring& params,
    uint32_t sei_addr, uint32_t* regs, EmulatedMemory& mem)
{
    LOG(API, "[API]   -> ARM PE detected, launching as child process\n");
    std::string narrow_path;
    for (auto c : mapped_file) narrow_path += (char)c;

    struct ChildProcInfo {
        std::string path;
        std::wstring cmdline;
        EmulatedMemory* mem;
        Win32Thunks* thunks;
    };
    auto* cpi = new ChildProcInfo{ narrow_path, params, &mem, this };

    DWORD realThreadId = 0;
    HANDLE hThread = ::CreateThread(NULL, 0,
        [](LPVOID param) -> DWORD {
            auto* cpi = (ChildProcInfo*)param;
            int thread_idx = g_next_thread_index.fetch_add(1);

            ThreadContext ctx;
            ctx.marshal_base = 0x3F000000 + (thread_idx + 1) * 0x10000;
            t_ctx = &ctx;

            /* Set process name from child path */
            {
                const char* p = cpi->path.c_str();
                const char* fname = strrchr(p, '/');
                if (!fname) fname = strrchr(p, '\\');
                fname = fname ? fname + 1 : p;
                snprintf(ctx.process_name, sizeof(ctx.process_name), "%s", fname);
                Log::SetProcessName(ctx.process_name, GetCurrentThreadId());
            }

            /* Create per-process virtual address space */
            ProcessSlot slot;
            if (!slot.buffer) {
                LOG(API, "[API] ShellExecuteEx: ProcessSlot alloc failed\n");
                delete cpi; t_ctx = nullptr; return 1;
            }
            EmulatedMemory::process_slot = &slot;

            /* Load PE into the slot */
            PEInfo child_pe = {};
            uint32_t entry = PELoader::LoadIntoSlot(
                cpi->path.c_str(), *cpi->mem, child_pe, slot);
            if (!entry) {
                LOG(API, "[API] ShellExecuteEx: LoadIntoSlot failed\n");
                EmulatedMemory::process_slot = nullptr;
                delete cpi; t_ctx = nullptr; return 1;
            }

            /* Allocate per-thread stack */
            uint32_t stack_top = 0x00FFFFF0;

            /* Initialize per-thread KData */
            InitThreadKData(&ctx, *cpi->mem, GetCurrentThreadId());
            EmulatedMemory::kdata_override = ctx.kdata;

            /* Set up CPU */
            ArmCpu& cpu = ctx.cpu;
            cpu.mem = cpi->mem;
            cpu.thunk_handler = [thunks = cpi->thunks](
                    uint32_t addr, uint32_t* r, EmulatedMemory& m) -> bool {
                if (addr == 0xDEADDEAD) {
                    LOG(EMU, "[EMU] Child process returned with code %d\n", r[0]);
                    return true;
                }
                if (addr == 0xCAFEC000) { r[15] = 0xCAFEC000; return true; }
                return thunks->HandleThunk(addr, r, m);
            };

            MakeCallbackExecutor(&ctx, *cpi->mem, *cpi->thunks, 0xCAFEC000);
            cpi->mem->Alloc(ctx.marshal_base, 0x10000);
            cpi->thunks->InstallThunks(child_pe);
            cpi->thunks->CallDllEntryPoints();

            /* Build command line in shared memory */
            uint32_t cmdline_addr = 0x60003000;
            cpi->mem->Alloc(cmdline_addr, 0x1000);
            for (size_t j = 0; j < cpi->cmdline.size() && j < 0x7FE; j++)
                cpi->mem->Write16(cmdline_addr + (uint32_t)(j * 2),
                                  (uint16_t)cpi->cmdline[j]);
            cpi->mem->Write16(cmdline_addr + (uint32_t)(cpi->cmdline.size() * 2), 0);

            /* Set up WinMain args */
            cpu.r[0] = child_pe.image_base;
            cpu.r[1] = 0;
            cpu.r[2] = cmdline_addr;
            cpu.r[3] = 1; /* SW_SHOWNORMAL */
            cpu.r[REG_SP] = stack_top;
            cpu.r[REG_LR] = 0xDEADDEAD;
            if (entry & 1) {
                cpu.cpsr |= PSR_T;
                cpu.r[REG_PC] = entry & ~1u;
            } else {
                cpu.r[REG_PC] = entry;
            }
            cpu.cpsr |= 0x13;

            LOG(API, "[PROC] Child process started: PC=0x%08X SP=0x%08X '%s'\n",
                cpu.r[REG_PC], stack_top, ctx.process_name);
            delete cpi;
            cpu.Run();

            uint32_t exit_code = cpu.r[0];
            LOG(API, "[PROC] Child process exited with code %u\n", exit_code);
            EmulatedMemory::process_slot = nullptr;
            EmulatedMemory::kdata_override = nullptr;
            t_ctx = nullptr;
            return exit_code;
        },
        cpi, 0, &realThreadId);

    if (!hThread) {
        LOG(API, "[API] ShellExecuteEx: CreateThread failed (err=%lu)\n", GetLastError());
        delete cpi;
        mem.Write32(sei_addr + 0x20, 0);
        regs[0] = 0;
        return true;
    }
    LOG(API, "[API]   -> child process thread=%u\n", realThreadId);
    mem.Write32(sei_addr + 0x20, 42);
    regs[0] = 1;
    return true;
}

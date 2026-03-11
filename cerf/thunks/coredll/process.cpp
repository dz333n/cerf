#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Process/thread thunks: CreateProcessW, CreateThread stubs, file mapping */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>


void Win32Thunks::RegisterProcessHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(API, "[API] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    Thunk("CreateThread", 492, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* CreateThread(lpSA, stackSize, lpStartAddress, lpParameter, flags, lpThreadId)
           ARM calling convention: R0=lpSA, R1=stackSize, R2=lpStartAddress, R3=lpParameter
           Stack: [0]=flags, [1]=lpThreadId */
        uint32_t lpStartAddress = regs[2];
        uint32_t lpParameter = regs[3];
        uint32_t flags = ReadStackArg(regs, mem, 0);
        uint32_t lpThreadId = ReadStackArg(regs, mem, 1);
        LOG(API, "[API] CreateThread(startAddr=0x%08X, param=0x%08X, flags=0x%X)\n",
            lpStartAddress, lpParameter, flags);

        if (!lpStartAddress) {
            LOG(API, "[API]   CreateThread: null start address\n");
            regs[0] = 0; return true;
        }

        /* Capture everything the new thread needs */
        struct ThreadStartInfo {
            uint32_t start_addr;
            uint32_t parameter;
            EmulatedMemory* mem;
            Win32Thunks* thunks;
            uint32_t sentinel;
            char parent_process[32];
            char parent_exe_path[512];
            ProcessSlot* parent_slot;
        };
        auto* info = new ThreadStartInfo{
            lpStartAddress, lpParameter, &mem, this, 0xCAFEC000, {}, {},
            EmulatedMemory::process_slot
        };
        if (t_ctx) {
            snprintf(info->parent_process, 32, "%s", t_ctx->process_name);
            snprintf(info->parent_exe_path, 512, "%s", t_ctx->exe_path);
        }

        DWORD realThreadId = 0;
        HANDLE hThread = ::CreateThread(NULL, 0,
            [](LPVOID param) -> DWORD {
                auto* info = (ThreadStartInfo*)param;
                int thread_idx = g_next_thread_index.fetch_add(1);

                /* Create per-thread context */
                ThreadContext ctx;
                ctx.marshal_base = 0x3F000000 + (thread_idx + 1) * 0x10000;
                t_ctx = &ctx;

                /* Inherit process name, exe path, and address space from parent */
                snprintf(ctx.process_name, sizeof(ctx.process_name), "%s",
                         info->parent_process);
                snprintf(ctx.exe_path, sizeof(ctx.exe_path), "%s",
                         info->parent_exe_path);
                Log::SetProcessName(ctx.process_name, GetCurrentThreadId());
                EmulatedMemory::process_slot = info->parent_slot;

                /* Allocate per-thread stack in emulated memory */
                uint32_t stack_size = 0x100000; /* 1MB */
                /* Thread stacks below 0x02000000 (WinCE 32MB slot boundary).
                   Range 0x01900000-0x01FFFFFF (7 thread slots). */
                uint32_t stack_bottom = 0x01900000 + thread_idx * stack_size;
                info->mem->Alloc(stack_bottom, stack_size);
                uint32_t stack_top = stack_bottom + stack_size - 16;

                /* Initialize per-thread KData */
                InitThreadKData(&ctx, *info->mem, GetCurrentThreadId());
                EmulatedMemory::kdata_override = ctx.kdata;

                /* Set up CPU */
                ArmCpu& cpu = ctx.cpu;
                cpu.mem = info->mem;
                cpu.thunk_handler = [thunks = info->thunks](
                        uint32_t addr, uint32_t* regs, EmulatedMemory& m) -> bool {
                    if (addr == 0xDEADDEAD) {
                        LOG(EMU, "[EMU] Thread returned with code %d\n", regs[0]);
                        return true; /* will cause halted check */
                    }
                    if (addr == 0xCAFEC000) {
                        regs[15] = 0xCAFEC000;
                        return true;
                    }
                    return thunks->HandleThunk(addr, regs, m);
                };

                /* Build callback_executor for this thread */
                MakeCallbackExecutor(&ctx, *info->mem, *info->thunks, info->sentinel);

                /* Allocate marshal buffer page */
                info->mem->Alloc(ctx.marshal_base, 0x10000);

                /* Set up initial registers */
                cpu.r[0] = info->parameter;
                cpu.r[REG_SP] = stack_top;
                cpu.r[REG_LR] = 0xDEADDEAD;
                if (info->start_addr & 1) {
                    cpu.cpsr |= PSR_T;
                    cpu.r[REG_PC] = info->start_addr & ~1u;
                } else {
                    cpu.r[REG_PC] = info->start_addr;
                }
                cpu.cpsr |= 0x13; /* SVC mode */

                LOG(API, "[THREAD] Started thread %d: PC=0x%08X SP=0x%08X param=0x%08X\n",
                    thread_idx, cpu.r[REG_PC], stack_top, info->parameter);
                delete info;

                cpu.Run();

                LOG(API, "[THREAD] Thread %d exited with R0=0x%X\n",
                    thread_idx, cpu.r[0]);
                t_ctx = nullptr;
                EmulatedMemory::kdata_override = nullptr;
                return cpu.r[0];
            },
            info,
            (flags & CREATE_SUSPENDED) ? CREATE_SUSPENDED : 0,
            &realThreadId);

        if (!hThread) {
            LOG(API, "[API]   CreateThread FAILED (err=%lu)\n", GetLastError());
            delete info;
            regs[0] = 0;
            return true;
        }

        LOG(API, "[API]   CreateThread: real thread handle=0x%p tid=%u\n",
            hThread, realThreadId);
        if (lpThreadId) mem.Write32(lpThreadId, realThreadId);
        regs[0] = WrapHandle(hThread);
        return true;
    });
    RegisterChildProcessHandler();
    Thunk("TerminateThread", 491, stub0("TerminateThread"));
    Thunk("ResumeThread", 500, stub0("ResumeThread"));
    Thunk("SetThreadPriority", 514, stub0("SetThreadPriority"));
    Thunk("GetExitCodeProcess", 519, stub0("GetExitCodeProcess"));
    Thunk("OpenProcess", 509, stub0("OpenProcess"));
    /* WaitForMultipleObjects moved to sync.cpp */
}

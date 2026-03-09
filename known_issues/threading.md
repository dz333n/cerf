# Threading in CERF

## Current Model: Single-Threaded with Pseudo-Threads

CERF runs all ARM code on a **single host thread**. There is no true concurrency — everything executes sequentially through the `callback_executor` mechanism.

### How it works

1. **callback_executor** (`main.cpp`): The core native→ARM transition mechanism.
   - Saves full CPU state (R0-R15, CPSR)
   - Sets up arguments per ARM calling convention (R0-R3, stack for 5th+)
   - Sets LR to sentinel address `0xCAFEC000`
   - Runs `CPU.Step()` in a loop until PC hits sentinel
   - Restores original CPU state, returns R0
   - Supports **nested callbacks** with depth tracking (e.g., WndProc dispatching a message that triggers another WndProc)

2. **CreateThread** (`process.cpp`, ordinal 492):
   - Does NOT create a real OS thread
   - Runs the thread function **inline synchronously** via callback_executor
   - Only executes if the thread start address is in EXE range (0x10000–0x100000); skips DLL thread functions that would block on WaitForMultipleObjects
   - Sets `in_pseudo_thread = true` so GetMessageW returns non-blocking (`PeekMessage` instead of blocking `GetMessage`)
   - Returns fake handle `0xBEEF0001`, fake thread ID `0x1001`

3. **WaitForSingleObject** (`process.cpp`, ordinal 497): Direct passthrough to native Win32.

4. **WaitForMultipleObjects** (`process.cpp`, ordinal 498):
   - **Caps timeout to 100ms** to prevent indefinite blocking (since signaling threads don't really exist)
   - Unwraps fake handles to real native handles

5. **Critical Sections** (ordinals 2-5): All no-ops (single-threaded, no contention possible).

6. **Events/Mutexes**: Created as real native Win32 objects. SetEvent/ResetEvent/PulseEvent work via `EventModify` (ordinal 494). Mutexes via `CreateMutexW`/`ReleaseMutex`.

7. **TLS** (`system.cpp`): Emulated via fixed memory page at `0xFFFFC800`.
   - 64 slots at `0xFFFFC01C` (slots 0-3 reserved by WinCE)
   - `TlsCall` (ordinal 520) allocates next slot
   - `TlsGetValue`/`TlsSetValue` (ordinals 15/16) read/write slots

### What works

- Apps that create threads for one-shot background work (compute, then exit) — thread function runs inline and returns
- Apps that use TLS for per-module storage (single thread, so TLS is just global storage)
- Apps that use events/mutexes for simple signaling between "threads" — events are real native objects
- Critical sections — no-ops are correct since there's no contention

### What breaks

- **Apps that spawn threads with their own message loops** (e.g., explorer's `HandleNewWindow2`):
  The thread's `GetMessage` loop blocks the callback_executor, so the parent `WaitForSingleObject` never returns. The child window works but at deeply nested callback depth.

- **Producer-consumer patterns**: A thread waiting for another thread to produce data will deadlock, since the producer never runs.

- **Thread synchronization with timeouts**: `WaitForMultipleObjects` caps timeout to 100ms, which is a workaround but can cause apps to spin or behave unexpectedly.

- **Multiple concurrent UI threads**: Only one message pump can run at a time. Second UI thread's message loop would starve the first.

## Roadmap: Future Threading

### Phase 1: Cooperative Multitasking (near-term)

Convert pseudo-threads to **fibers/coroutines**:
- Each "thread" gets its own fiber with saved CPU state + ARM register context
- Main loop round-robins between fibers, giving each a time slice
- When a fiber calls `WaitForSingleObject`/`GetMessage` and would block, yield to next fiber
- No real OS threads needed — still single-threaded, but multiple ARM execution contexts

**Benefits**: Fixes message-loop-per-thread pattern (explorer windows), producer-consumer with events, most WinCE threading patterns.

**Limitations**: No true parallelism. CPU-bound threads can still starve others without preemption.

### Phase 2: Preemptive Time-Slicing (medium-term)

Add a timer-based preemption mechanism:
- After N instructions (e.g., 10,000), forcibly yield to next fiber
- Simulates WinCE's preemptive round-robin scheduler
- Instruction counting is cheap since we're already in a step loop

**Benefits**: CPU-bound threads don't starve others. More accurate WinCE behavior.

### Phase 3: True OS Threads (long-term, optional)

Run each ARM thread on a real OS thread:
- Each thread gets its own `UnicornEngine` instance or equivalent
- Shared emulated memory needs synchronization (mutex on page tables)
- Thunk layer needs thread-safety (per-thread TLS, handle tables)
- callback_executor becomes per-thread

**Benefits**: True parallelism, accurate thread scheduling.

**Costs**: Massive complexity increase. Race conditions in emulated memory. Most WinCE apps don't need true parallelism — cooperative scheduling should suffice for 99% of cases.

### Recommended Path

Phase 1 (fibers) is the highest-value next step. It would fix:
- Explorer folder window creation (HandleNewWindow2 thread pattern)
- Any app using worker threads with event signaling
- COM apartment threading (STA message pumps)

Phase 2 adds robustness. Phase 3 is likely unnecessary for the WinCE app ecosystem.

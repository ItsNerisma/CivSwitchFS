// Core constants - SDK offsets discovered via static analysis (Ghidra)
// These are injected automatically by tools/bundle.mjs into the payload

// -- Filesystem API (nn::fs::*) --------------------------------------
const F_CreateFile  = sdk_base + 0xa6700n;
const F_OpenFile    = sdk_base + 0xa78a0n;   // nn::fs::OpenFile
const F_CloseFile   = sdk_base + 0xa5a70n;
const F_WriteFile   = sdk_base + 0xa5e00n;
const F_ReadFile    = sdk_base + 0xa5b80n;
const F_SetFileSize = sdk_base + 0xa6020n;
const F_Commit      = sdk_base + 0xa7de0n;
const F_DeleteFile  = sdk_base + 0xa6710n;
const F_CreateDir   = sdk_base + 0xa6890n;
const F_OpenDir     = sdk_base + 0xa7bb0n;
const F_ReadDir     = sdk_base + 0xa5840n;
const F_CloseDir    = sdk_base + 0xa57b0n;

// -- TLS / IPC internals (discovered via Ghidra + byte search) -------
const GADGET_READ_TLS     = sdk_base + 0x14ba80n;  // mrs x0, tpidrro_el0; ret - returns TLS address
const IPC_SEND_DISPATCHER = sdk_base + 0x14ba90n;  // checks tpidrro_el0, calls svc
const SVC_SEND_SYNC       = sdk_base + 0x168c4cn;  // svc #0x21 wrapper
const SVC_SEND_SYNC_UB    = sdk_base + 0x168c54n;  // svc #0x22 wrapper (user buffer)
const SVC_GETINFO         = sdk_base + 0x168ca4n;  // svc #0x29 wrapper (entry; svc at +0x168ca8)
const CUR_PROCESS_HANDLE  = 0xffff8001n;           // Horizon pseudo-handle for the current process

// -- Socket API (nn::socket::*) --------------------------------------
const F_Socket     = sdk_base + 0x14d4c0n;
const F_Bind       = sdk_base + 0x14d3b0n;
const F_Listen     = sdk_base + 0x14d440n;
const F_Accept     = sdk_base + 0x14d390n;
const F_Connect    = sdk_base + 0x14d3c0n;
const F_GetSockName = sdk_base + 0x14d410n;
const F_SetSockOpt = sdk_base + 0x14d460n;
const F_Recv       = sdk_base + 0x14d310n;
const F_Send       = sdk_base + 0x14d340n;
const F_SockClose  = sdk_base + 0x14d510n;

// -- Mount table / FS internals (confirmed by the reference port, same SDK) ---
const F_FindMount    = sdk_base + 0xaaf10n;   // nn::fs::detail::Find(FileSystemAccessor**, const char*)

// -- Service Manager (sm:) ------------------------------------------
const SM_Initialize  = sdk_base + 0x14c960n;  // InitializeHipcServiceResolution
const SM_GetService  = sdk_base + 0x14cab0n;  // ConnectToHipcService(out_handle, name)
const SM_Finalize    = sdk_base + 0x14c990n;  // FinalizeHipcServiceResolution

// -- Handle management ----------------------------------------------
const F_CloseHandle  = sdk_base + 0x168be4n;  // svc #0x16 wrapper

// -- Threading (nn::os::*) - offsets confirmed by the reference on same SDK -
const F_CreateThread  = sdk_base + 0x142180n;  // nn::os::CreateThread(thread, priority?, func, arg)
const F_JoinThread    = sdk_base + 0x142480n;  // nn::os::WaitForThread (join)
const F_ExitThread    = sdk_base + 0x142410n;  // nn::os::ExitCurrentThread
const F_Sleep         = sdk_base + 0x137100n;  // nn::os::SleepThread(nanoseconds)
const F_Tick          = sdk_base + 0x137240n;  // nn::os::GetSystemTick -> returns u64 counter
const SYSTEM_TICK_FREQUENCY_HZ = 31250000;      // native counter; legacy SDK frequency reports 19.2 MHz

// -- ROP frame gadgets (for worker thread execution chains) ----------
const GADGET_LOAD_TABLE   = sdk_base + 0x4e094n;   // loads function table, dispatches call
const GADGET_CALL4        = sdk_base + 0x359b88n;   // sets up 4 args from stack, calls function
const GADGET_SAVE_RESULT  = sdk_base + 0x19bcc0n;   // stores x0 to [addr], returns
const GADGET_LONGJMP      = sdk_base + 0x5511b4n;   // restores context from frame, starts chain
const GADGET_MEMSET       = sdk_base + 0x522af0n;   // memset(dst, val, len) - SDK implementation
const GADGET_MEMCPY       = sdk_base + 0x5224e0n;   // memcpy(dst, src, len) - SDK implementation

// -- Synchronization (nn::os::*) ------------------------------------
const F_WaitForAddress    = sdk_base + 0x168d1cn;  // WaitForAddress(addr, type, value, timeout_ns)
const F_SignalToAddress   = sdk_base + 0x168d24n;  // SignalToAddress(addr, type, value, count)

// -- Raw SVC wrappers (bare kernel calls, no nn::os bookkeeping) -----
// Source: the ns2jb CivSwitch port, hardware-qualified on the same build.
// Raw svcCreateThread bypasses the nn::os::CreateThread hang.
const SVC_CreateThread     = sdk_base + 0x168b2cn;  // svc #0x08; x0=&out_handle, x1=entry, x2=arg, x3=stack_top, w4=prio, w5=core
const SVC_StartThread      = sdk_base + 0x168b44n;  // svc #0x09; w0=handle
const SVC_ExitThread       = sdk_base + 0x168b4cn;  // svc #0x0A; never returns. NOT svc #0x07 (ExitProcess!)
const SVC_SleepThread      = sdk_base + 0x168b54n;  // svc #0x0B; x0=nanoseconds
const SVC_GetThreadPriority = sdk_base + 0x168b5cn; // x0=&out_prio, w1=handle
const SVC_GetThreadCoreMask = sdk_base + 0x168b7cn; // x0=&out_core, x1=&out_mask, w2=handle
const SVC_SetThreadCoreMask = sdk_base + 0x168b9cn; // w0=handle, w1=ideal_core, x2=mask
const SVC_CancelSync       = sdk_base + 0x168c0cn;  // svc #0x19; w0=handle
const SVC_GetThreadId      = sdk_base + 0x168c74n;  // x0=&out_id, w1=handle
const SVC_WaitSync         = sdk_base + 0x168bf4n;  // x0=&out_idx, x1=handles, w2=count, x3=timeout_ns

// -- nn::os thread manager list (for borrowing priority from live threads) --
const THREAD_MANAGER_PTR   = sdk_base + 0xb22280n;  // read64 -> manager; manager+0xF0 = list; +0x1D0 = sentinel
const MOUNT_TABLE_HEAD     = sdk_base + 0xb35870n;  // global mount table head (alternative to FindMount)

// -- Light events (nn::os, for inter-thread synchronization) ---------
const F_EventInit          = sdk_base + 0x1324e0n;  // nn::os::InitializeLightEvent
const F_EventSignal        = sdk_base + 0x132520n;  // nn::os::SignalLightEvent
const F_EventClear         = sdk_base + 0x132640n;  // nn::os::ClearLightEvent
const F_EventWait          = sdk_base + 0x132680n;  // nn::os::WaitLightEvent

// -- Hashing ---------------------------------------------------------
const F_SHA256             = sdk_base + 0x4d40n;    // nn::crypto::GenerateSha256Hash(out, outSize, in, inSize)

// -- Additional memory -----------------------------------------------
const GADGET_MEMMOVE       = sdk_base + 0x522830n;  // memmove(dst, src, len)

// -- System ----------------------------------------------------------
const F_ShowAppError = sdk_base + 0x311620n;  // nn::err::ShowApplicationError

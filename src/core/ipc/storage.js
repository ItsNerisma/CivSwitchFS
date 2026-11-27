// IStorage helpers: open a content storage, read it, and get its size.

/*
 * Open a content storage with cmd 200 on a root fsp-srv session.
 *
 * Returns the IStorage handle (u32), or 0 on failure.
 */
function openContentStorage(rootSession) {
    var pkt = allocPage(0x2000);
    prepPacket(pkt, 4, 8, [[16, 0x49434653], [24, 200]]);
    sendIPC(rootSession, pkt);
    var reply = cmifReply(pkt);

    if (reply.result !== 0 || reply.moves.length !== 1) {
        for (var i = 0; i < reply.moves.length; i++) {
            closeHandle(reply.moves[i]);
        }
        for (var i = 0; i < reply.copies.length; i++) {
            closeHandle(reply.copies[i]);
        }
        return 0;
    }

    return reply.moves[0];
}

/*
 * IStorage::OperateRange (cmd 5) with operation 2, which discards the cache entries
 * covering the requested range. A clean entry, one that was never written through
 * IStorage::Write, is dropped without a flush, so nothing reaches the NAND.
 *
 * SAFETY: only call this when the handle has not issued IStorage::Write since the
 * cache was modified. Invalidating a dirty entry can flush it instead, so dirty
 * entries have to go through the retained-endpoint retirement path.
 */
function ipcStorageInvalidate(storageHandle, offset, size) {
    var pkt = allocPage(0x2000);
    /* OperateRange takes {u32 operation, u32 padding, s64 offset, s64 size}. The
     * 24-byte CMIF input needs 14 HIPC raw words, the same packet shape as the
     * reference ports.
     */
    prepPacket(pkt, 4, 0x0E, []);
    write32(pkt + 0x10n, 0x49434653n);
    write32(pkt + 0x18n, 5n);                    // cmd 5 = OperateRange
    write32(pkt + 0x20n, 2n);                    // operation = 2 (invalidate)
    write64(pkt + 0x28n, BigInt(offset));         // offset
    write64(pkt + 0x30n, BigInt(size));           // size
    var transport = Number(sendIPC(storageHandle, pkt)) >>> 0;

    if (transport !== 0) {
        return { error: transport, transport: transport };
    }

    var reply = cmifReply(pkt);
    return { error: reply.result, transport: 0 };
}

// IStorage::GetSize (cmd 4). Returns { error, size }, with size as a Number.
function ipcStorageGetSize(storageHandle) {
    var pkt = allocPage(0x2000);
    prepPacket(pkt, 4, 8, [[16, 0x49434653], [24, 4]]);
    sendIPC(storageHandle, pkt);
    var reply = cmifReply(pkt);

    if (reply.result !== 0) {
        return { error: reply.result, size: 0 };
    }

    var lo = Number(read32(pkt + BigInt(reply.data))) >>> 0;
    var hi = Number(read32(pkt + BigInt(reply.data + 4))) >>> 0;
    return { error: 0, size: lo + hi * 0x100000000 };
}

/*
 * IStorage::Read (cmd 0) with a B descriptor: read `size` bytes from `offset`
 * into `outputBuf`.
 *
 * Returns { error, canonicalError, transport, cmifError }.
 */
function ipcStorageRead(storageHandle, offset, size, outputBuf) {
    var pkt = allocPage(0x2000);
    // HIPC: type 4 with 1 B descriptor, and 0x0C raw words like the reference packet.
    prepPacket(pkt, (4 | (1 << 24)) >>> 0, 0x0C, []);
    // B descriptor, 3 words at offset 8: size, addr_low, flags|addr_high.
    write32(pkt + 8n, BigInt(size));
    write32(pkt + 12n, BigInt(Number(outputBuf & 0xFFFFFFFFn)));
    write32(pkt + 16n, BigInt(((1 |
        (Number((outputBuf >> 36n) & 7n) << 2) |
        (Number((outputBuf >> 32n) & 15n) << 28)) >>> 0)));
    // SFCI at 0x20: 5 header and descriptor words, padded to 16 bytes.
    write32(pkt + 0x20n, 0x49434653n);
    write32(pkt + 0x28n, 0n);                    // cmd 0 = Read
    write64(pkt + 0x30n, BigInt(offset));         // offset
    write64(pkt + 0x38n, BigInt(size));           // size
    var transport = Number(sendIPC(storageHandle, pkt)) >>> 0;

    if (transport !== 0) {

        /*
         * Read is command 0, so running cmifReply() on an untouched request packet
         * would read the request's own command id as a successful SFCO result.
         */
        return { error: transport, canonicalError: null,
            transport: transport, cmifError: null };
    }

    var reply = cmifReply(pkt);
    return { error: reply.result, canonicalError: reply.result & 0x3FFFFF,
        transport: transport, cmifError: reply.result };
}

/*
 * IStorage::Write (cmd 1) with an A (send) descriptor: write `size` bytes from
 * `inputBuf` to `offset`, then return the CMIF result.
 *
 * This is a low-level primitive. Callers validate the target themselves and keep
 * their own before/after snapshots and restoration logic.
 */


function ipcStorageWrite(storageHandle, offset, inputBuf, size) {
    var writeOffset = BigInt(offset);
    var inputAddress = BigInt(inputBuf);
    var writeSize = BigInt(size);

    if (isInvalidStorageWriteRange(writeOffset, inputAddress, writeSize)) {
        return { error: 0xFFFFFFFF, canonicalError: 0xFFFFFFFF };
    }

    var pkt = allocPage(0x2000);

    /*
     * HIPC type 4 with one A (send) descriptor, and SFCI at +0x20. Write has two u64
     * CMIF inputs (offset and size) just like Read, so raw_words is 0x0C.
     */
    prepPacket(pkt, (4 | (1 << 20)) >>> 0, 0x0C, []);
    var descriptorFlags = 1n |
        ((inputAddress >> 36n) << 2n) |
        ((writeSize >> 32n) << 24n) |
        (((inputAddress >> 32n) & 0xFn) << 28n);
    write32(pkt + 0x08n, writeSize & 0xFFFFFFFFn);
    write32(pkt + 0x0Cn, inputAddress & 0xFFFFFFFFn);
    write32(pkt + 0x10n, descriptorFlags & 0xFFFFFFFFn);
    write32(pkt + 0x20n, 0x49434653n);
    write32(pkt + 0x28n, 1n);                       // cmd 1 = Write
    write64(pkt + 0x30n, writeOffset);              // offset
    write64(pkt + 0x38n, writeSize);                // size
    var transport = Number(sendIPC(storageHandle, pkt)) >>> 0;
    var reply = cmifReply(pkt);
    return { error: reply.result,
        canonicalError: reply.result & 0x3FFFFF,
        transport: transport };
}

/*
 * Clone a domain session with Control cmd 2 (CloneCurrentObject).
 *
 * Returns a new independent handle to the same filesystem, or 0 on failure.
 */
function cloneFsSession(sourceHandle) {
    var pkt = allocPage(0x2000);
    prepPacket(pkt, 5, 8, [
        [16, 0x49434653], [24, 2], [32, 0]
    ]);
    sendIPC(sourceHandle, pkt);
    var reply = cmifReply(pkt);

    if (reply.result !== 0 || reply.moves.length === 0) {
        return 0;
    }

    return reply.moves[0];
}

function isInvalidStorageWriteRange(writeOffset, inputAddress, writeSize) {
    return writeOffset < 0n || writeOffset >= (1n << 63n) ||
        inputAddress < 0n || inputAddress >= (1n << 39n) ||
        writeSize <= 0n || writeSize > 0xFFFFFFFFFn;
}

// HIPC transport helpers: packet construction, descriptors and dispatch.

// ----- Low-level IPC -----

/*
 * Zero a buffer, write its HIPC header, then apply the extra words.
 *
 *   tag0  = HIPC word0 (type plus descriptor counts)
 *   tag1  = HIPC word1 (raw_words plus flags)
 *   words = [[offset, value], ...], the extra u32 writes
 */
function prepPacket(buf, tag0, tag1, words) {
    for (let i = 0n; i < 0x200n; i += 8n) {
        write64(buf + i, 0n);
    }
    write32(buf, BigInt(tag0 >>> 0));
    write32(buf + 4n, BigInt(tag1 >>> 0));
    for (const [off, v] of words) {
        write32(buf + BigInt(off), BigInt(v >>> 0));
    }
}

/*
 * Write the header of a type-2 domain request, the kind that addresses one object
 * of the session's domain table in word 0x14. The command word at 0x18 stays zero,
 * so the caller still chooses which command it sends.
 */
function writeDomainRequestHeader(buf, objectId) {
    prepPacket(buf, 4, 8, []);
    write8(buf + 0x10n, 2n);
    write32(buf + 0x14n, BigInt(objectId));
    write32(buf + 0x1Cn, 0n);
}

/*
 * Write an X (pointer) buffer descriptor at the given offset. The layout comes
 * from Switchbrew:
 *
 *   word0 bits 31:16 = size, 15:12 = address[35:32], 8:6 = address[38:36], 5:0 = index
 *   word1 = addr[31:0]
 *
 * descriptorIndex is the descriptor's rank in the request's X-descriptor list.
 */
function writeXDesc(buf, descOffset, dataAddr, dataSize, descriptorIndex) {
    descriptorIndex = descriptorIndex || 0;
    const addrLow  = Number(dataAddr & 0xFFFFFFFFn);
    const addr3235 = Number((dataAddr >> 32n) & 0xFn);
    const addr3638 = Number((dataAddr >> 36n) & 0x7n);
    const word0 = (dataSize << 16) | (addr3638 << 6) | (addr3235 << 12) |
        (descriptorIndex & 0x3F);
    write32(buf + BigInt(descOffset), BigInt(word0 >>> 0));
    write32(buf + BigInt(descOffset + 4), BigInt(addrLow >>> 0));
}

/*
 * Send an IPC message through the dispatcher, from a heap buffer. A buffer that
 * differs from tpidrro_el0 is what forces the svc #0x22 path.
 */
function sendIPC(handle, buf) {
    return call_rop(IPC_SEND_DISPATCHER, BigInt(handle), buf, 0x1000n);
}

// Close a kernel handle through the svc #0x16 wrapper.
function closeHandle(handle) {
    return call_rop(F_CloseHandle, BigInt(handle));
}

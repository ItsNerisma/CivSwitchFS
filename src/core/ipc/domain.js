// Domain IPC helpers: build and send commands to CMIF domain objects.

/**
 * Send a CMIF request to a domain object, using the documented request and
 * response layout.
 *
 * `buf` has to be an allocPage'd buffer of at least 0x2000 bytes.
 * Request: domain header at +0x10, SFCI at +0x20, input at +0x30.
 * Response: object count at +0x10, SFCO at +0x20, then data and IDs at +0x30.
 *
 * @param {number} handle Domain session handle.
 * @param {number} targetObj Target domain object ID.
 * @param {number} cmdId CMIF command ID.
 * @param {bigint} buf IPC buffer address.
 * @param {Function} inputFn Optional request-data writer.
 * @param {number} inputBytes Number of input-data bytes.
 * @returns {object} Transport status, CMIF result, and returned object count.
 */
function sendDomainCmd(handle, targetObj, cmdId, buf, inputFn, inputBytes) {
    inputBytes = inputBytes || 0;
    var sfciPayload = 16 + inputBytes;
    for (var i = 0n; i < 0x200n; i += 8n) {
        write64(buf + i, 0n);
    }
    write32(buf, 4n);
    write32(buf + 4n, BigInt(12 + Math.ceil(inputBytes / 4)));
    write32(buf + 0x10n, BigInt(1 | (sfciPayload << 16)));
    write32(buf + 0x14n, BigInt(targetObj));
    write32(buf + 0x20n, 0x49434653n);
    write32(buf + 0x28n, BigInt(cmdId));

    if (inputFn) {
        inputFn();
    }

    var trc = sendIPC(handle, buf);
    var transport = Number(trc) >>> 0;
    var rspMagic = Number(read32(buf + 0x20n)) >>> 0;

    if (rspMagic !== 0x4F434653) {
        return { ok: false, result: -1, transport: transport, objCount: 0 };
    }

    var result = Number(read32(buf + 0x28n)) >>> 0;
    var objCount = Number(read32(buf + 0x10n)) >>> 0;
    return { ok: true, result: result, transport: transport, objCount: objCount };
}

/** Read the domain object IDs that follow `dataSize` bytes of response data. */
function readDomainObjects(buf, objCount, dataSize) {
    var objs = [];
    var off = 0x30 + (dataSize || 0);
    for (var i = 0; i < objCount && i < 8; i++) {
        objs.push(Number(read32(buf + BigInt(off + i * 4))) >>> 0);
    }
    return objs;
}

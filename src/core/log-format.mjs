/*
 * Log formatting for the payload supervisor.
 *
 * Pure functions only: no IPC, no logging, no side effects. Each one turns a
 * result object into the string the stage log prints.
 */

// ----- Primitives -----

export function formatCode(value) {
    if (value === null || value === undefined) {
        return "n/a";
    }

    return "0x" + (Number(value) >>> 0).toString(16).padStart(8, "0");
}

function seconds(ms) {
    return (ms / 1000).toFixed(1) + "s";
}

function median(values) {
    const sorted = values.filter(v => Number.isFinite(v))
        .slice().sort((a, b) => a - b);

    if (!sorted.length) {
        return null;
    }

    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2
        ? sorted[mid]
        : (sorted[mid - 1] + sorted[mid]) / 2;
}

function displayUs(value) {
    return "~" + Math.round(value) + "µs";
}


// ----- Labels -----

const ROLE_NAMES = {
    commit: "Commit worker",
    bottleneck: "Bottleneck read worker",
    frag0: "Fragment worker 0",
    frag1: "Fragment worker 1",
    frag2: "Fragment worker 2",
    frag3: "Fragment worker 3",
    canary: "Canary lookup worker",
    filler0: "Filler worker 0",
    filler1: "Filler worker 1",
    release: "Release worker",
    guard0: "Guard worker 0",
    guard1: "Guard worker 1",
    trigger: "Trigger worker"
};

function humanRoleName(role) {
    return ROLE_NAMES[role] || role;
}

function humanStopReason(control) {
    const reason = control.workflowStopReason;

    if (!reason) {
        return control.controlsQualified
            ? "positive attempt limit reached"
            : "control sequence incomplete";
    }

    let match = /^dirty-write-failed-at-wave-(\d+)$/.exec(reason);

    if (match) {
        return "dirty-file write failed at wave " + match[1];
    }

    match = /^reservation-failed-at-wave-(\d+)$/.exec(reason);

    if (match) {
        return "reservation setup failed at wave " + match[1];
    }

    match = /^worker-start-failed-at-wave-(\d+)$/.exec(reason);

    if (match) {
        return "workers failed to start at wave " + match[1];
    }

    match = /^worker-join-failed-at-wave-(\d+)$/.exec(reason);

    if (match) {
        return "workers failed to join at wave " + match[1];
    }

    match = /^profile-setup-failed-(.+)$/.exec(reason);

    if (match) {
        return "could not configure the " + match[1] + " profile";
    }

    match = /^worker-pinning-failed-at-wave-(\d+)$/.exec(reason);

    if (match) {
        return "could not pin all workers before wave " + match[1];
    }

    return reason.replace(/-/g, " ");
}


// ----- Simple formatters -----

/** One-line reason and detail suffix appended to a failed step result. */
export function formatFailureSuffix(result) {
    if (!result?.failureReason) {
        return "";
    }

    return " (reason=" + result.failureReason +
        (result.failureDetail ? "; detail=" + result.failureDetail : "") + ")";
}

/** Elapsed time, formatted as the suffix of the alias status line. */
export function formatAliasTiming(elapsedMs) {
    return " (elapsed " + seconds(elapsedMs) + ")";
}


// ----- Address qualification -----

/** One verbose line per measured address-qualification stage. */
export function formatAddressResults(address, elapsedMs) {
    const p = address.timingProfile || {};
    const addressReads = p.addressReads || 0;
    const metadata = p.metadata || 0;
    const pages = p.pages || 0;
    const root = p.root || 0;
    const period = p.period || 0;

    const addressStatus = address.addressReadVerified ? "passed" : "rejected";
    let aliasStatus;

    if (address.addressAliasRequalified === null) {
        aliasStatus = "not run";
    } else if (address.addressAliasRequalified) {
        aliasStatus = "passed";
    } else {
        aliasStatus = "failed";
    }

    let periodStatus;

    if (address.bucketPeriodQualified === null) {
        periodStatus = "not run";
    } else if (address.bucketPeriodQualified) {
        periodStatus = "passed";
    } else {
        periodStatus = "failed";
    }

    let rootStatus;

    if (address.rootStageVerified) {
        rootStatus = "verified";
    } else if (address.addressReadVerified) {
        rootStatus = "not verified";
    } else {
        rootStatus = "not checked";
    }

    const failureParts = [];

    if (address.addressFailureReason) {
        failureParts.push("; reason=" +
            address.addressFailureReason.replace(/-/g, " "));
    }

    if (address.addressFailureDetail) {
        failureParts.push("; detail=" + address.addressFailureDetail);
    }

    if (address.storageSizeError !== null) {
        failureParts.push("; storageSizeError=" +
            formatCode(address.storageSizeError));
    }

    const failureInfo = failureParts.join("");

    return [
        "Address: " + addressStatus + " · candidates=" + address.addressCandidatesTested + " · valid plans=" + address.validAddressPlans +
            " · alias=" + aliasStatus + " · bucket period=" + periodStatus + " · " + seconds(addressReads + period) +
            failureInfo,

        "Metadata: anchors=" + address.metadataAnchorChecks + " · pages=" + address.metadataPageChecks +
            " · probes=" + address.metadataPageProbes + " · " + seconds(metadata + pages),

        "FSP root: " + rootStatus + " · candidates=" + address.rootCandidateScans +
            " · PID=" + (address.rootPidRead ? "read" : "not read") + " · scan=" + seconds(root) + " · total=" + seconds(elapsedMs)
    ];
}


// ----- Timing analysis -----

// Names the workers that timed badly in the positive waves a gate rejected.
function collectTimingIssues(control, config) {
    const records = control.positiveWindowRecords || [];
    const rejected = records.filter(r => !r.window);
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

        if (Number.isFinite(delta)) {
            issue.values.push(delta);
        }
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

            if (timing.relStartUs >= 0) {
                addIssue(role, "late-start", timing.relStartUs, record.wave);
            }

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

    // Sort by rejected-wave count, then by median timing deviation.
    const ordered = Object.keys(issues).map(k => issues[k])
        .sort((a, b) => b.count - a.count ||
            (median(b.values) || 0) - (median(a.values) || 0));

    const messages = ordered.slice(0, 6).map(issue => {
        const count = issue.count + "/" + rejected.length + " rejected waves";

        if (issue.kind === "unmeasured") {
            return humanRoleName(issue.role) + " timing unavailable (" + count + ")";
        }

        const amount = median(issue.values);

        if (issue.kind === "late-start") {
            return amount === 0
                ? humanRoleName(issue.role) + " started at trigger start; it must start earlier (" +
                    count + ")"
                : humanRoleName(issue.role) + " started " +
                    displayUs(amount) + " after trigger start (" + count + ")";
        }

        const boundary = issue.kind === "early-end-through"
            ? "trigger end" : "trigger start";
        return amount === 0
            ? humanRoleName(issue.role) + " ended at " + boundary + "; it must run longer (" + count + ")"
            : humanRoleName(issue.role) + " ended " + displayUs(amount) + " before " + boundary + " (" + count + ")";
    });

    if (triggerSpanMissing) {
        messages.unshift("Trigger timing unavailable (" + triggerSpanMissing + "/" + rejected.length + " rejected waves)");
    }

    if (ordered.length > 6) {
        messages.push((ordered.length - 6) + " more worker timing issues");
    }

    return {rejected, messages};
}

function summarizePinQualification(control) {
    if (control.pinFirstWaveQualified) {
        return "";
    }

    const pin = control.pinQualificationDiagnostics;

    if (!pin) {
        const attempted = (control.profileCounts || {})["abort-control"] || 0;
        return attempted
            ? "Initial cache pin qualification failed; timing details unavailable."
            : "";
    }

    const issues = [];

    if (!pin.shapeOk) {
        issues.push("pin IPC reply shape failed");
    }

    if (!pin.costOk) {
        issues.push("pin allocation size did not match expected");
    }

    if (!pin.restored) {
        issues.push("heap counters did not restore");
    }

    if (!pin.windowMeasured) {
        issues.push("canary/pin timing spans were not measured");
    } else {
        if (pin.startOffsetUs <= 0) {
            const gap = Math.abs(pin.startOffsetUs);
            issues.push(gap === 0
                ? "Cache pin worker started with Canary; it must start after it"
                : "Cache pin worker started " + displayUs(gap) + " too early relative to Canary");
        }

        if (pin.endMarginUs <= 0) {
            const gap = Math.abs(pin.endMarginUs);
            issues.push(gap === 0
                ? "Cache pin worker ended with Canary; it must finish first"
                : "Cache pin worker ended " + displayUs(gap) + " too late relative to Canary");
        }

        if (!pin.windowOk && pin.startOffsetUs > 0 && pin.endMarginUs > 0) {
            issues.push("Cache pin timing did not fit inside the Canary span");
        }
    }

    return issues.length
        ? "Initial pin: " + issues.join("; ") + "."
        : "Initial cache pin qualification failed.";
}


// ----- Gate rejection summary -----

const GATE_LABELS = {
    reservation: "reservation group incomplete",
    "workers-done": "not all workers completed",
    transport: "an IPC send failed",
    "workers-join": "not all workers joined",
    "protected": "protected worker completion flags missing",
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

/*
 * The gate keys that carry real content, where a plain label says nothing: each
 * one has its own summarizer fed by the timing records. summarizeRejectedGates
 * skips these keys and runs those summarizers instead.
 */
const GATE_SPECIALIZED = new Set([
    "shape", "margin>=300", "pre-release", "trig-span", "pin-window", "pin-1st"
]);

/*
 * The gate keys whose summary needs the rejection records rather than a count.
 * summarizeOrdinaryGate hands them to their own summarizer.
 */
const GATE_DEDICATED = new Set(["no-abort", "paths"]);



function summarizeNoAbortGate(count, total, timing) {
    const samples = (timing.rejected || [])
        .map(record => record.guardSamples).filter(Boolean);
    const kinds = [];

    if (samples.some(sample => sample.completed)) {
        kinds.push("completion");
    }

    if (samples.some(sample => sample.earlyHole)) {
        kinds.push("early-hole");
    }

    if (samples.some(sample => sample.spacing)) {
        kinds.push("spacing");
    }

    return "worker abort guard fired" +
        (kinds.length ? " (" + kinds.join(", ") + ")" : "") + " (" + count + "/" + total + ")";
}

function summarizePathGate(count, total, timing) {
    const changed = new Set();
    for (const record of timing.rejected || []) {
        if ((record.rejections || []).indexOf("paths") < 0) {
            continue;
        }

        for (const path of record.changedPaths || []) {
            changed.add(path);
        }
    }
    const names = Array.from(changed).map(humanRoleName);

    return names.length
        ? "unexpected result from " + names.join(", ") + " (" + count + "/" + total + ")"
        : "canary/filler/guard result did not match expected status (" +
            count + "/" + total + ")";
}

function summarizeOrdinaryGate(key, count, total, timing) {
    if (!GATE_DEDICATED.has(key)) {
        return (GATE_LABELS[key] || key.replace(/-/g, " ")) + " (" + count + "/" + total + ")";
    }

    if (key === "no-abort") {
        return summarizeNoAbortGate(count, total, timing);
    }

    return summarizePathGate(count, total, timing);
}

function summarizeShapeGate(counts, timing) {
    if (counts.shape && !timing.messages.length) {
        return "required worker overlap pattern did not qualify";
    }

    return null;
}

function summarizeTriggerSpanGate(counts, timing) {
    if (counts["trig-span"] && !timing.messages.some(message =>
        message.startsWith("Trigger timing"))) {
        return "Trigger worker span was not measured";
    }

    return null;
}

function summarizeMarginGate(counts, total, timing) {
    if (!counts["margin>=300"]) {
        return null;
    }

    const marginRecords = (timing.rejected || []).filter(record =>
        (record.rejections || []).indexOf("margin>=300") >= 0);
    const margins = marginRecords.map(record => record.marginUs);
    const shortages = marginRecords.map(record => record.marginSlackUs)
        .filter(Number.isFinite).map(value => Math.max(0, -value));
    const typicalMargin = median(margins);
    const typicalShortage = median(shortages);

    if (typicalMargin === null) {
        return "Bottleneck/Guard 1 overlap margin was not measured";
    }

    return "Bottleneck/Guard 1 overlap was " +
        displayUs(typicalMargin) + " (needs 300µs" +
        (typicalShortage === null ? ")"
            : "; short by " + displayUs(typicalShortage) + ")") + " (" + counts["margin>=300"] + "/" + total + ")" +
        "; extend Bottleneck or start Guard 1 earlier";
}

function summarizePreReleaseGate(counts, total, timing) {
    if (!counts["pre-release"]) {
        return null;
    }

    const shortages = (timing.rejected || []).filter(record =>
        (record.rejections || []).indexOf("pre-release") >= 0)
        .map(record => record.preReleaseSlackBytes)
        .filter(Number.isFinite).map(value => Math.max(0, -value));
    const typicalShortage = median(shortages);

    if (typicalShortage === null) {
        return "pre-release cache hold was not measured";
    }

    return "pre-release cache hold was ~" + Math.round(typicalShortage) +
        "B below the 0x2600-byte minimum (" + counts["pre-release"] + "/" + total + ")";
}

function summarizeRejectedGates(control, timing) {
    const counts = control.positiveGateFailures || {};
    const total = (control.positiveWindowRecords || []).length;
    const entries = [];

    for (const [key, count] of Object.entries(counts)) {
        // The dedicated summaries below own these keys.
        if (isSpecialGateSummaryKey(key)) {
            continue;
        }

        entries.push(summarizeOrdinaryGate(key, count, total, timing));
    }

    for (const summary of [
        summarizeShapeGate(counts, timing),
        summarizeTriggerSpanGate(counts, timing),
        summarizeMarginGate(counts, total, timing),
        summarizePreReleaseGate(counts, total, timing)
    ]) {
        if (summary) {
            entries.push(summary);
        }
    }

    const pinIssue = summarizePinQualification(control);

    if (pinIssue) {
        entries.push(pinIssue);
    }

    return entries;
}


// ----- Canary result -----

const CANARY_STATE_LABELS = {
    "controls-incomplete": "control sequence incomplete",
    "no-qualified-positive-window": "no qualified positive window",
    "window-valid-no-flip": "qualified window, no flip",
    "raw-flip-outside-window": "flip outside qualified window",
    "post-health-failure": "post-flip health check failed",
    "worker-unsafe": "worker state unsafe",
    "user-stopped": "stopped by user"
};

/** Full canary summary: control waves, the gates of each positive wave, and the timing verdict. */
export function formatCanaryResult(control, config) {
    if (!control) {
        return "Canary run failed before returning a result.";
    }

    const counts = control.profileCounts || {};
    const controls = [
        ["pin", (counts["abort-control"] || 0) > 0,
            control.pinFirstWaveQualified],
        ["abort", (counts["abort-control"] || 0) > 0,
            control.abortControlPassed],
        ["hole", (counts["abort-hole-control"] || 0) > 0,
            control.abortHoleControlPassed],
        ["extent", (counts["extent-present"] || 0) > 0,
            control.extentQualified],
        ["negative", (counts.negative || 0) > 0,
            control.negativeControlPassed]
    ];
    const failedControls = controls
        .filter(([, attempted, passed]) => attempted && !passed)
        .map(([name]) => name);

    const timing = collectTimingIssues(control, config);
    const otherIssues = summarizeRejectedGates(control, timing);

    const label = CANARY_STATE_LABELS[control.campaignState] || control.campaignState;
    const healthIssue = control.positiveHealthFailures
        ? ["post-wave canary health failed " +
            control.positiveHealthFailures + " time(s)"] : [];
    const totalIssues = [...new Set([
        ...timing.messages, ...healthIssue, ...otherIssues
    ])];
    const issueSummary = totalIssues.length
        ? "; issue=" + totalIssues.slice(0, 2).join("; ") +
            (totalIssues.length > 2 ? "; +" + (totalIssues.length - 2) + " more" : "")
        : "";
    const positiveSummary = control.positiveAttempts
        ? "positive=" + control.positiveAttempts + " waves, windows=" + control.positiveWindows + "/" +
            control.positiveAttempts + ", qualified flips=" +
            control.positiveQualifiedFlips +
            (control.positiveOutsideWindowFlips
                ? ", outside-window flips=" + control.positiveOutsideWindowFlips
                : "")
        : "positive waves=not run";
    const controlSummary = control.controlsQualified
        ? "controls=passed"
        : failedControls.length
            ? "controls failed=" + failedControls.join(",")
            : "controls incomplete";

    if (control.canaryQualified) {
        return "CANARY FLIPPED · " + positiveSummary;
    }

    const outcome = control.campaignState === "worker-unsafe"
        ? "Canary aborted"
        : control.campaignState === "user-stopped"
            ? "Canary stopped"
            : control.campaignState === "post-health-failure"
                ? "Canary flip rejected"
                : "Canary not qualified";
    return outcome + " (" + label + ") · " + controlSummary + " · " + positiveSummary +
        " · workers=" + (control.workerStateSafe ? "safe" : "unsafe") + " · stop=" + humanStopReason(control) +
        issueSummary;
}


// ----- Alias result -----

/** Full copy-wave summary for a single alias installation. */
export function formatAliasResult(alias) {
    if (alias.aliasInstalled) {
        return "Cache alias installed · " + alias.copyStepsCompleted + "/7 steps · " + alias.copyWavesTotal + " total copy waves.";
    }

    const reasons = Object.entries(alias.copyFailureCounts || {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 2)
        .map(([reason, count]) => reason.replace(/-/g, " ") + " " + count)
        .join(", ") || "none";

    const failedSteps = (alias.copyStepFailures || []).map(step =>
        step.step + " (" + step.reason.replace(/-/g, " ") + ", " + step.attempts + " tries)")
        .join(",") || "none";

    return "Cache alias rejected · " + alias.copyStepsCompleted + "/7 steps · " + alias.copyWavesTotal + " total copy waves · workers=" +
        (alias.workerStateSafe ? "safe" : "unsafe") + " · main cause=" + (alias.copyFailureReason || "unknown").replace(/-/g, " ") +
        " · frequent failures=" + reasons + " · failed steps=" + failedSteps + ".";
}


// ----- Promotion result -----

/** Name the prerequisite that blocks promotion. It only labels the reason; it never decides whether promotion runs. */
export function promotionSkipReason(address, handles) {
    if (!address.addressReadVerified) {
        return "address-read-not-qualified";
    }

    if (!address.rootStageVerified) {
        return "root-identity-not-verified";
    }

    if (!address.verifiedIdentityTargets) {
        return "identity-targets-unavailable";
    }

    if (!handles.domainSession) {
        return "domain-session-unavailable";
    }

    if (!handles.candidateHandle) {
        return "candidate-storage-unavailable";
    }

    if (!address.addressPlan) {
        return "address-plan-unavailable";
    }

    return "promotion-precondition-failed";
}

function getPromotionPidStatus(promotion, outcome) {
    if (outcome?.promoted) {
        return "verified";
    }

    if (promotion.promotionAttempted) {
        return "failed";
    }

    return "skipped";
}

function getPromotionUserFsStatus(promotion, outcome) {
    if (!promotion.promotionAttempted || !outcome?.promoted) {
        return "not attempted";
    }

    if (outcome.openedUserFs) {
        return "opened";
    }

    return "failed";
}

function getPromotionListingStatus(outcome) {
    if (!outcome?.promoted || !outcome.openedUserFs) {
        return "not attempted";
    }

    if (outcome.listedUserRoot) {
        return "read";
    }

    return "failed";
}

function getPromotionRestoreStatus(promotion) {
    if (!promotion.promotionAttempted) {
        return "not needed";
    }

    if (promotion.promotionRestored) {
        return "verified";
    }

    return "failed";
}

/** Promotion report: PID state, User access, the directory listing and the restore state. */
export function formatPromotionResult(promotion, address, handles) {
    const outcome = promotion.promotionOutcome;
    const pidStatus = getPromotionPidStatus(promotion, outcome);
    const userFsStatus = getPromotionUserFsStatus(promotion, outcome);
    const listingStatus = getPromotionListingStatus(outcome);
    const restoreStatus = getPromotionRestoreStatus(promotion);

    let msg = "PID fields " + pidStatus + "; User filesystem " + userFsStatus + "; root listing " + listingStatus;

    if (outcome?.listedUserRoot) {
        msg += "(" + outcome.listCount + " entries)";
    }

    msg += "; restore=" + restoreStatus;

    if (!promotion.promotionAttempted) {
        msg += "; reason=" +
            promotionSkipReason(address, handles).replace(/-/g, " ");
    }

    if (outcome?.error) {
        msg += "; reason=" + outcome.error;
    }

    if (outcome && !promotion.promotionRestored &&
        outcome.restoreFailureDetails?.length) {
        msg += "; restoreFailures={" +
            outcome.restoreFailureDetails.join(",") + "}";
    }

    if (outcome?.openedUserFs && !outcome.listedUserRoot) {
        msg += "; listError=" + formatCode(outcome.listResult) + "; listTransport=" + formatCode(outcome.listTransport) +
            "; entriesRead=" + outcome.listEntriesRead;
    }

    if (promotion.promotionAttempted && outcome?.promoted &&
        !outcome?.openedUserFs) {
        msg += "; openError=" + outcome.error + "; transport=" + formatCode(outcome.openTransport) +
            "; result=" + formatCode(outcome.openResult) + "; objects=" + outcome.openObjects;
    }

    if (outcome?.fsCloseResult !== undefined &&
        outcome?.fsCloseResult !== 0) {
        msg += "; UserFS-closeError=" + formatCode(outcome.fsCloseResult);
    }

    return msg;
}


// ----- Cleanup and retirement -----

/** One cleanup verdict line: what was deleted, committed and closed. */
export function formatCleanupResult(cleanup, workerStateSafe) {
    const counts = "handlesClosed=" + cleanup.handlesClosed + "/" + cleanup.expectedHandles;

    if (cleanup.cleanupVerified) {
        return "Cleanup complete (" + counts + ").";
    }

    if (cleanup.skipped) {
        return "Cleanup skipped (worker state " +
            (workerStateSafe ? "safe" : "unsafe") + "; reason=" +
            (cleanup.skipReason || "unknown").replace(/-/g, " ") + "; " + counts + ").";
    }

    return "Cleanup failed (" + counts + "; deleteTransport=" + formatCode(cleanup.deleteTransport) +
        "; deleteResult=" + formatCode(cleanup.deleteResult) + "; commitTransport=" + formatCode(cleanup.commitTransport) +
        "; commitResult=" + formatCode(cleanup.commitResult) + "; closeErrors=" +
            ((cleanup.closeErrors || []).join(",") || "none") + "; errors=" +
            ((cleanup.errors || []).join(",") || "none") + ").";
}

/** One retirement verdict line: cache state, endpoint state and the handle left open. */
export function formatRetirementResult(retired) {
    if (retired?.failureReason ===
        "candidate-cache-invalidation-unconfirmed") {
        return "Candidate cache invalidation was not confirmed; candidate storage remains open.";
    }

    if (retired?.failureReason ===
        "candidate-cache-verification-unconfirmed") {
        return "Candidate cache readback was not confirmed; cache state remains unconfirmed.";
    }

    if (!retired?.ok || retired?.failureReason) {
        return "Endpoint retirement or close failed (reason=" +
            (retired?.failureReason || "cleanup-safety-not-verified") + "; close=" + formatCode(retired?.candidateCloseResult) + ").";
    }

    if (retired.addressCopy?.candidateCacheVerification ===
        "fresh-readback-original") {
        return "Candidate cache readback passed on a fresh storage; candidate storage closed.";
    }

    if (retired.candidateCacheRetired) {
        return "Candidate cache retired and candidate storage closed.";
    }

    if (!retired.candidateHandle) {
        return "Endpoint retirement was not needed; candidate storage closed.";
    }

    return "Endpoint retirement is incomplete; candidate storage remains open.";
}

function isSpecialGateSummaryKey(key) {
    return GATE_SPECIALIZED.has(key);
}

/*
 * Retuning only happens between two attempts, and only from failed positive waves
 * that hit exactly one rejection. Control waves and waves that already passed the
 * window gate do not count.
 */
const TIMING_MIN_FAILED_WAVES = 2;
const TIMING_NOISE_FLOOR_US = 75;
const TIMING_MAX_STEP_US = 150;
const TIMING_MAX_DRIFT_US = 1000;
const TIMING_MIN_ROLE_GAP_NS = 50000;
const RECEIVE_MARGIN_TARGET_US = 500;

/**
 * Fit the next timing schedule to the qualified positive waves. One role delay
 * moves per proposal, and the gate that rejected the most waves picks it.
 *
 * Only repeated waves with a single rejection feed this, and the change stays
 * bounded.
 */
export function proposePositiveTimingAdjustment(records, config) {
    const eligible = records.filter(record => {
        const reasons = record.rejections || [];
        return !record.window && reasons.length === 1 &&
            (reasons[0] === "shape" || reasons[0] === "margin>=300");
    });

    if (eligible.length < TIMING_MIN_FAILED_WAVES) {
        return null;
    }

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

            if (!trigger) {
                continue;
            }

            for (const missingRole of new Set(record.shapeMissing || [])) {
                if (missingRole === "guard1" ||
                    config.roleLabels.indexOf(missingRole) < 0) {
                    continue;
                }

                const timing = timings[missingRole];

                if (!timing) {
                    continue;
                }

                let targetMidpoint;

                if (config.throughRoles.indexOf(missingRole) >= 0) {
                    const triggerDuration = trigger.relEndUs - trigger.relStartUs;

                    if (timing.durationUs <= triggerDuration) {
                        continue;
                    }

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
                    (corrections[missingRole] = [])).push(targetMidpoint - midpoint);
            }
        }
        const ranked = Object.entries(corrections)
            .filter(([, values]) => values.length >= TIMING_MIN_FAILED_WAVES)
            .sort((a, b) => b[1].length - a[1].length);

        if (!ranked.length || (ranked[1] &&
            ranked[0][1].length === ranked[1][1].length)) {
            return null;
        }

        role = ranked[0][0];
        samples = ranked[0][1];
        reason = "positive-window-shape";
    } else {
        return null;
    }

    const correctionUs = median(samples);

    if (!Number.isFinite(correctionUs) ||
        Math.abs(correctionUs) < TIMING_NOISE_FLOOR_US) {
        return null;
    }

    const stepUs = Math.max(-TIMING_MAX_STEP_US,
                            Math.min(TIMING_MAX_STEP_US, correctionUs));
    const roleIndex = config.roleLabels.indexOf(role);
    const isGuard = role === "guard0" || role === "guard1";
    const delayIndex = isGuard ? roleIndex - 10 : roleIndex;
    // Build the proposal on copies so this attempt's schedule stays unchanged.
    const roleDelays = config.roleDelays.slice();
    const guardDelays = config.guardDelays.slice();
    const delays = isGuard ? guardDelays : roleDelays;
    let defaults;

    if (isGuard) {
        defaults = config.baselineGuardDelays;
    } else {
        defaults = config.baselineRoleDelays;
    }

    if (delayIndex < 0 || delayIndex >= delays.length) {
        return null;
    }

    const before = delays[delayIndex];
    let minDelay = Math.max(0, defaults[delayIndex] - TIMING_MAX_DRIFT_US * 1000);
    let maxDelay = defaults[delayIndex] + TIMING_MAX_DRIFT_US * 1000;

    if (delayIndex > 0) {
        minDelay = Math.max(minDelay,
                            delays[delayIndex - 1] + TIMING_MIN_ROLE_GAP_NS);
    }

    if (delayIndex + 1 < delays.length) {
        maxDelay = Math.min(maxDelay,
                            delays[delayIndex + 1] - TIMING_MIN_ROLE_GAP_NS);
    }

    if (minDelay > maxDelay) {
        return null;
    }

    const after = Math.max(minDelay, Math.min(maxDelay,
                                              before + Math.round(stepUs * 1000)));
    const actualStepUs = (after - before) / 1000;

    if (!actualStepUs) {
        return null;
    }

    delays[delayIndex] = after;
    return {role, deltaUs: actualStepUs, reason,
        roleDelays, guardDelays};
}

/**
 * Format the verbose counter-vector line for one recorded positive wave. The
 * 16-field report is written as hex, and since peaks clear on read, each vector
 * covers its own measurement window only.
 */
export function formatWaveVectorLine(record, config) {
    const result = record.result;
    const roleTimings = result.roleTimings;
    const parts = [
        "vec: w=" + record.wave,
        "p=" + record.profile,
        "win=" + (result.window ? 1 : 0),
        "flip=" + (result.canaryRedirect ? 1 : 0),
        "obs=" + (result.observedCanaryRedirect ? 1 : 0),
        "shape=" + result.shape + "/" + config.OVERLAP_COUNT,
        "m=" + formatMargin(result.marginUsRaw),
        "w9=" + Math.round(record.w9DelayNs / 1000) + "us",
        "trg=0x" + Number(result.triggerCanonical).toString(16) + "/" + result.triggerType,
        "selected=" + (result.selectedMarker ? 1 : 0),
        "canaryRes=0x" + Number(result.canaryResult).toString(16),
        "canaryType=" + result.canaryType,
        "abort=" + (result.triggerAborted ? 1 : 0),
        "postHealthy=" + (result.postCanaryHealth.healthy ? 1 : 0),
        "postTransport=" + result.postCanaryHealth.transport,
        "postRes=0x" + Number(result.postCanaryHealth.result).toString(16),
        "postType=" + result.postCanaryHealth.type,
        "changed=" + formatListOrDash(result.changedPaths),
        "reject=" + formatListOrDash(result.rejections)
    ];
    const guards = result.guardSamples || {};
    parts.push("guards=c:" + (guards.completed ?? "na") + ",h:" + (guards.earlyHole ?? "na") + ",s:" + (guards.spacing ?? "na"));

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

            if (timing) {
                ipc.push(Math.round(timing.durationUs));
            }
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

function median(values) {
    if (!values.length) {
        return null;
    }

    const sorted = values.slice().sort((a, b) => a - b);
    const middle = Math.floor(sorted.length / 2);

    if (sorted.length % 2 !== 0) {
        return sorted[middle];
    }

    return (sorted[middle - 1] + sorted[middle]) / 2;
}

function formatCounterVector(values) {
    if (!values) {
        return "na";
    }

    const parts = [];
    for (let i = 0; i < values.length; i++) {
        parts.push(values[i].toString(16));
    }
    return parts.join(",");
}

function formatProbeUs(value) {
    if (!Number.isFinite(value)) {
        return "na";
    }

    return String(Math.round(value));
}

function formatMargin(value) {
    if (value === null) {
        return "na";
    }

    return String(Math.round(value));
}

function formatListOrDash(values) {
    if (!values.length) {
        return "-";
    }

    return values.join(",");
}

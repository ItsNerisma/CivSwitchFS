const WAVE_REJECTION_LABELS = {
    reservation: "reservations",
    "workers-done": "workers incomplete",
    transport: "IPC failed",
    "workers-join": "workers did not join",
    "protected": "worker flags",
    "release-sent": "release failed",
    signal: "completion signal",
    "trig-span": "trigger timing unavailable",
    "shape": "overlap pattern",
    "margin>=300": "margin below 300µs",
    "no-abort": "unexpected abort",
    tails: "path fragments",
    commit: "save commit",
    read: "storage read",
    paths: "path results",
    "pin-shape": "pin reply",
    "clear-ok": "heap clear",
    "pre-ok": "heap probe",
    "heap-restore": "heap counters",
    "pin-cost": "pin allocation",
    "pin-window": "pin timing",
    "pin-1st": "initial pin",
    "pre-release": "cache hold"
};

/** One verbose wave line: status, gates, timing, and the cache and path fields. */
export function formatWaveSummaryLine(id, profile, result, verdict, config) {
    const status = waveStatus(profile, result, verdict);
    const isCacheProfile = isCacheCopyProfile(profile, verdict);
    let line = "Wave " + pad2(id) + " [" + profile + "] " + status;
    line += formatWaveProfileFields(profile, result);

    if (result.margin != null) {
        line += " · margin=" + result.margin + "/300µs";
    }

    if (profile === "positive" && result.canaryRedirect) {
        line += " · post-check=OK";
    }

    line += formatWaveCacheField(isCacheProfile, result, config);
    line += formatWavePathReplyField(result);

    if (result.renameInputDiagnostics) {
        line += " · " + formatRenameInputDiagnostics(result.renameInputDiagnostics);
    }

    line += formatWaveRejectionField(status, result, config, profile, verdict);
    return line + formatWaveHealthField(result);
}

function pad2(n) {
    return n < 10 ? "0" + n : "" + n;
}

function waveStatus(profile, result, verdict) {
    if (profile === "abort-control") {
        return result.abortControl ? "PASS · expected abort" : "REJECTED";
    }

    if (profile === "abort-hole-control") {
        return result.abortHoleControl ? "PASS · expected abort" : "REJECTED";
    }

    if (profile === "extent-present") {
        return result.extentQualified ? "PASS · marker found" : "REJECTED";
    }

    if (profile === "negative") {
        return result.negativeControl ? "PASS · expected error" : "REJECTED";
    }

    if (profile === "positive") {
        if (result.canaryRedirect) {
            return "QUALIFIED FLIP";
        }

        if (result.observedCanaryRedirect && !result.window) {
            return "FLIP OUTSIDE WINDOW";
        }

        if (result.window) {
            return "WINDOW OK · no flip";
        }

        return "REJECTED";
    }

    if (profile === "extent-absent") {
        return "REFERENCE";
    }

    if (profile.indexOf("cache") === 0 ||
        /accepted|copy-ok/i.test(String(verdict || ""))) {
        return /accepted|copy-ok/i.test(String(verdict || ""))
            ? "ACCEPTED" : "REJECTED";
    }

    return verdict || (result.window ? "WINDOW OK" : "REJECTED");
}

function isCacheCopyProfile(profile, verdict) {
    return profile.indexOf("cache") === 0 ||
        /header copy/i.test(String(verdict || ""));
}

function fallbackWaveRejection(result, profile) {
    if (profile === "abort-control" || profile === "abort-hole-control") {
        return "abort check did not match";
    }

    if (profile === "extent-present") {
        return "marker result did not match";
    }

    if (profile === "negative") {
        return "expected error was not returned";
    }

    if (profile === "positive") {
        return result.window
            ? "canary did not flip" : "window gates did not qualify";
    }

    if (result.changedPaths?.length) {
        return "changed paths: " + result.changedPaths.join(",");
    }

    return "";
}

function formatWaveRejectionSummary(reasons) {
    if (reasons.length > 2) {
        return reasons.slice(0, 2).join(", ") + " +" +
            (reasons.length - 2) + " checks";
    }

    return reasons.join(", ");
}

function waveRejectionSummary(result, config, profile, verdict) {
    const reasons = [];
    for (const key of result.rejections || []) {
        let label = WAVE_REJECTION_LABELS[key] || key.replace(/-/g, " ");

        if (key === "shape") {
            label += " " + result.shape + "/" + config.OVERLAP_COUNT;
        }

        if (key === "paths" && result.changedPaths?.length) {
            label += ": " + result.changedPaths.join(",");
        }

        if (!reasons.includes(label)) {
            reasons.push(label);
        }
    }

    if (isCacheCopyProfile(profile, verdict) && result.window) {
        if (result.preReleaseUsed == null ||
            result.preReleaseUsed < config.FIELD_MINIMUM_CACHE_HELD) {
            reasons.push("cache hold below minimum");
        } else if (result.changedPaths?.length) {
            reasons.push("unexpected path result");
        }
    }

    if (result.postCanaryHealth && !result.postCanaryHealth.healthy) {
        reasons.push("post-wave canary health");
    }

    if (!reasons.length) {
        const fallback = fallbackWaveRejection(result, profile);

        if (fallback) {
            reasons.push(fallback);
        }
    }

    return formatWaveRejectionSummary(reasons);
}

function formatPathReplyCode(value) {
    if (value == null) {
        return "na";
    }

    var raw = Number(value) >>> 0;

    if (raw === 0xFFFFFFFF) {
        return "send-failed";
    }

    var canonical = raw & 0x3FFFFF;
    return raw === canonical
        ? "0x" + raw.toString(16)
        : "0x" + raw.toString(16) + "/0x" + canonical.toString(16);
}

function formatRenameInputDiagnostics(diagnostics) {
    if (!diagnostics) {
        return "path-inputs=unavailable";
    }

    var labels = [
        ["src", "fillerSource"], ["dst", "fillerDestination"],
        ["guard0", "guardSource"], ["guard1", "guardDestination"]
    ];
    var summaries = [];
    for (var i = 0; i < labels.length; i++) {
        var label = labels[i][0];
        var name = labels[i][1];
        var before = diagnostics.before?.[name];
        var after = diagnostics.after?.[name];

        if (!before?.available || !after?.available) {
            summaries.push(label + "=unavailable");
            continue;
        }

        var beforeStatus = before.matchesExpected ? "ok" : "diff@" +
            (before.firstDiff ? before.firstDiff.offset : "?");
        var afterStatus = after.matchesExpected ? "ok" : "diff@" +
            (after.firstDiff ? after.firstDiff.offset : "?");
        var status = beforeStatus + ">" + afterStatus +
            (before.hash !== after.hash ? "/mutated" : "");
        summaries.push(label + "/" + before.size + "=0x" +
            before.hash.toString(16) + ">0x" + after.hash.toString(16) + "/" + status);
    }
    var descriptorStatus = diagnostics.descriptorsOk ? "ok" : "bad";

    if (!diagnostics.descriptorsOk && diagnostics.descriptors?.roles) {
        var badRoles = diagnostics.descriptors.roles.filter(role =>
            role.descriptors.some(desc => !desc.matchesExpected));
        descriptorStatus += ":" + badRoles.map(role => "W" + role.role + "[" +
            role.descriptors.map((desc, index) => index + ":" +
                desc.index + "/" + desc.size + "@0x" +
                desc.address.toString(16) + "/0x" +
                desc.word0.toString(16) + "/0x" +
                desc.word1.toString(16)).join(",") + "]").join(";");
    }

    return "path-inputs=" + summaries.join(",") + ";xdesc=" +
        descriptorStatus;
}

function formatWaveProfileFields(profile, result) {
    let fields = "";

    if (profile === "extent-absent") {
        fields += " · window=" + (result.window ? "OK" : "no");

        if (result.triggerCanonical != null) {
            fields += " · trigger=0x" +
                Number(result.triggerCanonical).toString(16);
        }
    }

    if (["abort-control", "abort-hole-control", "extent-present",
        "negative", "extent-absent", "positive"].indexOf(profile) >= 0 &&
        result.canaryType != null) {
        fields += " · canary=" + (result.canaryType === 1 ? "file" :
            result.canaryType === 0 ? "DIR" : "error");
    }

    if (profile === "abort-control" && result.pinDiagnostics?.created) {
        fields += " · pin=" + (result.pinFirstWaveQualified
            ? "OK" : "not qualified");
    }

    return fields;
}

function formatWaveCacheField(isCacheProfile, result, config) {
    if (!isCacheProfile) {
        return "";
    }

    const held = result.preReleaseUsed == null
        ? "n/a" : "0x" + Number(result.preReleaseUsed).toString(16);
    return " · cache=" + held + "/0x" +
        Number(config.FIELD_MINIMUM_CACHE_HELD).toString(16);
}

function formatWavePathReplyField(result) {
    if (!result.pathReplyResults) {
        return "";
    }

    const paths = result.pathReplyResults;
    const parts = [];

    if (paths.filler0 != null) {
        parts.push("f0:" + formatPathReplyCode(paths.filler0));
    }

    if (paths.filler1 != null) {
        parts.push("f1:" + formatPathReplyCode(paths.filler1));
    }

    parts.push("g0:" + formatPathReplyCode(paths.guard0));
    parts.push("g1:" + formatPathReplyCode(paths.guard1));
    return " · RenameFile=" + parts.join(",");
}

function formatWaveRejectionField(status, result, config, profile, verdict) {
    if (status === "REJECTED" || status === "FLIP OUTSIDE WINDOW") {
        const reasons = waveRejectionSummary(result, config, profile, verdict);
        return reasons ? " · cause: " + reasons : "";
    }

    return "";
}

function formatWaveHealthField(result) {
    if (result.postCanaryHealth && !result.postCanaryHealth.healthy) {
        return " · post-check failed";
    }

    return "";
}

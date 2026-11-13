// Wave diagnostic recorder — accumulates per-wave telemetry in memory.
// Zero async calls during recording (no timing disruption between waves).
// Print structured report after the campaign.
//
// Depends on: format.js (ticksToUs)

// ── Window qualification with rejection tracking ─────────────────
// Takes { name: boolean } conditions, returns { ok, rejections[] }.
// Use instead of a giant Boolean AND so each failing check is named.
function checkWindow(conditions) {
    var rejections = [];
    var keys = Object.keys(conditions);
    for (var i = 0; i < keys.length; i++) {
        if (!conditions[keys[i]]) rejections.push(keys[i]);
    }
    return { ok: rejections.length === 0, rejections: rejections };
}

// ── Role timing extraction ───────────────────────────────────────
// Compute each role's timing relative to the trigger span start.
// Returns { roleName: { relStartUs, relEndUs, durationUs } }.
function extractRoleTimings(spans, trigSpan) {
    var timings = {};
    var ref = trigSpan ? trigSpan.start : 0n;
    for (var i = 0; i < spans.length; i++) {
        var s = spans[i];
        timings[s.name] = {
            relStartUs: trigSpan ? ticksToUs(s.start - ref) : 0,
            relEndUs:   trigSpan ? ticksToUs(s.end   - ref) : ticksToUs(s.end - s.start),
            durationUs: ticksToUs(s.end - s.start)
        };
    }
    return timings;
}

// ── Diagnostic recorder ──────────────────────────────────────────
//
// Usage:
//   var diag = createWaveDiag();
//
//   // inside wave loop (synchronous, no await):
//   diag.record({
//     waveId:          attempt,       // 0-based wave index
//     profile:         "positive",    // wave profile name
//     shapeCount:      10,            // overlap shape count (out of 10)
//     marginUs:        1355.2,        // receive margin in microseconds (null if NA)
//     canaryType:      1,             // 0=DIR, 1=file, 2+=err
//     windowQualified: true,          // final window boolean
//     rejections:      [],            // from checkWindow()
//     postHealthy:     true,          // canary health after wave
//     canaryRedirect:  false,         // actual redirect achieved
//     verdict:         "miss",        // human-readable verdict string
//     roleTimings:     timings,       // from extractRoleTimings()
//     preReleaseUsed:  0x2810,        // bytes used before release (optional)
//     triggerAborted:  false          // abort guard fired (optional)
//   });
//
//   // after campaign:
//   var lines = diag.report();
//   for (var i = 0; i < lines.length; i++) await log(lines[i]);

function createWaveDiag() {
    var records = [];

    function p2(n) { return n < 10 ? "0" + n : "" + n; }
    function pR(s, w) { while (s.length < w) s += " "; return s; }
    function pL(s, w) { while (s.length < w) s = " " + s; return s; }

    return {
        record: function(entry) { records.push(entry); },
        count:  function() { return records.length; },
        raw:    function() { return records; },

        report: function() {
            if (records.length === 0) return ["(no waves recorded)"];
            var lines = [];
            var total = records.length;

            // ── Per-wave table ──────────────────────────────────
            lines.push("=== WAVE DIAGNOSTICS: " + total + " waves ===");
            lines.push("W## | profile             | shape | margin   | canary | win | hlth | verdict          | rejection");
            lines.push("----|---------------------|-------|----------|--------|-----|------|------------------|----------");

            for (var i = 0; i < total; i++) {
                var r = records[i];
                var can = r.canaryType === 0 ? "DIR" :
                    r.canaryType === 1 ? "file" :
                    r.canaryType >= 2 ? "err" : "?";
                var mar = r.marginUs != null
                    ? r.marginUs.toFixed(0) + "us" : "NA";
                var rej = r.rejections && r.rejections.length > 0
                    ? r.rejections.join(", ") : "-";

                lines.push(
                    p2((r.waveId || 0) + 1) + "  | " +
                    pR(r.profile || "?", 19) + " | " +
                    pR((r.shapeCount != null ? r.shapeCount : "?") + "/10", 5) + " | " +
                    pL(mar, 8) + " | " +
                    pR(can, 6) + " | " +
                    pR(r.windowQualified ? "YES" : "no", 3) + " | " +
                    pR(r.postHealthy ? "OK" : "BAD", 4) + " | " +
                    pR(r.verdict || "?", 16) + " | " +
                    rej
                );
            }

            // ── Aggregates ──────────────────────────────────────
            var canChg = 0, winOk = 0, hpOk = 0, redir = 0;
            var posN = 0, posR = 0;
            var margins = [];

            for (var i = 0; i < total; i++) {
                var r = records[i];
                if (r.canaryType !== 1) canChg++;
                if (r.windowQualified) winOk++;
                if (r.postHealthy) hpOk++;
                if (r.canaryRedirect) redir++;
                var isPos = r.profile === "positive" ||
                    (r.profile && r.profile.indexOf("cache") === 0);
                if (isPos) { posN++; if (r.canaryRedirect) posR++; }
                if (r.marginUs != null) margins.push(r.marginUs);
            }

            lines.push("");
            lines.push("--- AGGREGATES ---");
            lines.push("Total: " + total +
                " | canary changed: " + canChg +
                " | window OK: " + winOk +
                " | health OK: " + hpOk +
                " | redirects: " + redir);

            if (posN > 0)
                lines.push("Positive/cache: " + posN + " waves, " +
                    posR + " redirects (" +
                    (100 * posR / posN).toFixed(0) + "%)");

            if (margins.length > 0) {
                margins.sort(function(a, b) { return a - b; });
                var sum = 0;
                for (var i = 0; i < margins.length; i++) sum += margins[i];
                lines.push("Margin: min=" + margins[0].toFixed(0) +
                    "us  avg=" + (sum / margins.length).toFixed(0) +
                    "us  max=" + margins[margins.length - 1].toFixed(0) + "us");
            }

            // ── Rejection reasons breakdown ─────────────────────
            var rc = {};
            for (var i = 0; i < total; i++) {
                if (!records[i].rejections) continue;
                for (var j = 0; j < records[i].rejections.length; j++) {
                    var k = records[i].rejections[j];
                    rc[k] = (rc[k] || 0) + 1;
                }
            }
            var rk = Object.keys(rc);
            if (rk.length > 0) {
                rk.sort(function(a, b) { return rc[b] - rc[a]; });
                lines.push("");
                lines.push("--- REJECTION REASONS ---");
                for (var i = 0; i < rk.length; i++)
                    lines.push("  " + rc[rk[i]] + "x " + rk[i]);
            }

            // ── Per-wave key timing ─────────────────────────────
            // Show commit/trigger/canary timing per wave to
            // correlate redirect success with specific timings.
            var hasTimings = false;
            for (var i = 0; i < total; i++) {
                if (records[i].roleTimings) { hasTimings = true; break; }
            }
            if (hasTimings) {
                lines.push("");
                lines.push("--- PER-WAVE TIMING (us, vs trigger start) ---");
                lines.push("W## | commit_start | commit_dur | commit_end | trig_dur | canary_dur | overlap | result");
                lines.push("----|-------------|------------|------------|----------|------------|---------|-------");

                for (var i = 0; i < total; i++) {
                    var r = records[i];
                    var rt = r.roleTimings;
                    if (!rt) continue;
                    var cm = rt["commit"];
                    var tr = rt["trigger"];
                    var cn = rt["canary"];
                    var cmEnd = cm ? cm.relStartUs + cm.durationUs : null;
                    var overlap = cmEnd != null && cmEnd > 0;
                    var res = r.canaryRedirect ? "REDIR" :
                        r.canaryType === 0 ? "DIR" :
                        r.canaryType === 1 ? "file" : "err";

                    lines.push(
                        p2((r.waveId || 0) + 1) + "  | " +
                        pL(cm ? cm.relStartUs.toFixed(0) : "?", 11) + " | " +
                        pL(cm ? cm.durationUs.toFixed(0) : "?", 10) + " | " +
                        pL(cmEnd != null ? cmEnd.toFixed(0) : "?", 10) + " | " +
                        pL(tr ? tr.durationUs.toFixed(0) : "?", 8) + " | " +
                        pL(cn ? cn.durationUs.toFixed(0) : "?", 10) + " | " +
                        pR(overlap ? "YES" : cmEnd != null ? "no" : "?", 7) + " | " +
                        res
                    );
                }
            }

            // ── Role timing distribution (aggregate) ────────────
            var allRoles = {};
            for (var i = 0; i < total; i++) {
                if (!records[i].roleTimings) continue;
                var ks = Object.keys(records[i].roleTimings);
                for (var j = 0; j < ks.length; j++) allRoles[ks[j]] = true;
            }
            var rn = Object.keys(allRoles);
            if (rn.length > 0) {
                lines.push("");
                lines.push("--- ROLE TIMING RANGES (vs trigger start, us) ---");
                for (var ri = 0; ri < rn.length; ri++) {
                    var name = rn[ri];
                    var st = [], du = [];
                    for (var wi = 0; wi < total; wi++) {
                        if (!records[wi].roleTimings) continue;
                        var rt = records[wi].roleTimings[name];
                        if (!rt) continue;
                        st.push(rt.relStartUs);
                        du.push(rt.durationUs);
                    }
                    if (st.length === 0) continue;
                    st.sort(function(a, b) { return a - b; });
                    du.sort(function(a, b) { return a - b; });
                    lines.push("  " + pR(name, 12) +
                        "start=" + pL(st[0].toFixed(0), 7) + ".." +
                        pL(st[st.length - 1].toFixed(0), 7) +
                        "  dur=" + pL(du[0].toFixed(0), 6) + ".." +
                        pL(du[du.length - 1].toFixed(0), 6) +
                        "  (n=" + st.length + ")");
                }
            }

            return lines;
        }
    };
}

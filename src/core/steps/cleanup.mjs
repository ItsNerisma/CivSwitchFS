import coreRuntime from "../runtime.mjs";
import {log, verboseLog} from "../logger.mjs";
import {readEntryTypeChecked} from "../ipc/entry-type.mjs";
import {formatCode} from "../log-format.mjs";

const {
    allocPage,
    call_rop,
    closeHandle,
    GADGET_MEMSET,
    hex32,
    ipcCommitChecked,
    ipcDeleteDirectoryRecursivelyChecked,
    ipcFileInvalidate,
    ipcStorageInvalidate,
    ipcStorageGetSize,
    ipcStorageRead,
    openContentStorage
} = coreRuntime;

// ----- Endpoint retirement and cleanup (S21 and S22) -----

const FALLBACK_HOLE_PATH = "/hole";
const ENTRY_NOT_FOUND = 0x202;

/**
 * S21: retire the candidate cache entry and the retained endpoint, then close the
 * candidate handle. `retainedEndpointActive` picks the recovery path.
 *
 * State A has an installed alias and no IStorage::Write through it. The clean
 * cache entry is invalidated, then the original bytes are verified through a
 * fresh storage handle.
 *
 * State B has an active retained endpoint and PID writes through IStorage. Its
 * zero-count layout is verified, then the endpoint is retired, and that entry is
 * never invalidated. When retirement fails the attempt stops, because the state it
 * leaves behind is unknown.
 *
 * Every failure below leaves an endpoint in an unknown state, so all early returns
 * go through the same builder and mark the state unsafe.
 */
export async function retireCandidateCacheAndClose({
    helpers,
    addressCopy,
    candidateCacheNeedsRetirement,
    candidateHandle,
    rootSession,
    retireRetainedEndpoint,
    workerStateSafe,
}) {
    let candidateCacheRetired = false;
    let candidateCloseSafe = workerStateSafe;
    const workersQuiesced = workerStateSafe === true;
    const stateSafe = workerStateSafe === true;
    let candidateCloseResult = null;
    let retirementFailureReason = null;

    const failRetirement = (failureReason, extra = {}) => {
        addressCopy = {...addressCopy, retainedEndpointUnsafe: true,
            workerStateSafe: false};
        return {ok: false, addressCopy, candidateCacheRetired, candidateHandle,
            workerStateSafe: false, workersQuiesced, failureReason, ...extra};
    };

    if (addressCopy && addressCopy.retainedEndpointActive) {
        if (!candidateCloseSafe || !candidateHandle ||
            typeof retireRetainedEndpoint !== "function") {
            await log(formatUnsafeState("Retained endpoint cannot be retired."));
            return failRetirement("retained-endpoint-state-unsafe");
        }

        try {
            const retainedRetirement = await retireRetainedEndpoint();

            if (!retainedRetirement || !retainedRetirement.retired) {
                throw new Error("retained endpoint did not confirm retirement");
            }

            addressCopy = retainedRetirement.addressCopy || addressCopy;
        } catch (retirementError) {
            await log(formatUnsafeState("Retained endpoint retirement failed: " +
                retirementError.message));
            return failRetirement("retained-endpoint-retirement-failed: " +
                retirementError.message);
        }

        try {
            candidateCloseResult = Number(closeHandle(candidateHandle)) >>> 0;

            if (candidateCloseResult !== 0) {
                return failRetirement("retained-candidate-close-failed",
                                      {candidateCloseResult});
            }

            candidateHandle = 0;
            candidateCacheRetired = true;
            addressCopy = {...addressCopy, retainedEndpointActive: false,
                retainedEndpointRetired: true, candidateCacheRetired: true};
        } catch (closeError) {
            return failRetirement("retained-candidate-close-threw: " +
                                  closeError.message, {candidateCloseResult});
        }
        return {ok: true, addressCopy, candidateCacheRetired,
            candidateHandle, candidateCloseResult,
            workerStateSafe: stateSafe, workersQuiesced};
    }

    /*
     * State A: the alias exists but nothing was written through it. Invalidate the
     * clean entry, then prove the original bytes through a fresh storage handle.
     */
    if (candidateHandle && candidateCacheNeedsRetirement && candidateCloseSafe) {
        let storageInvalidated = false;

        const storageSize = ipcStorageGetSize(candidateHandle);

        if (storageSize.error === 0 &&
            Number.isSafeInteger(storageSize.size) && storageSize.size > 0) {
            const invalidation = ipcStorageInvalidate(candidateHandle, 0, storageSize.size);
            storageInvalidated = invalidation.error === 0;
            await verboseLog("CLEANUP: storage cache invalidate result=" + hex32(invalidation.error) +
                " transport=" + hex32(invalidation.transport));
        }

        if (storageInvalidated) {
            const verification = await verifyInvalidatedCandidateCache({
                candidateHandle, helpers, addressCopy, rootSession
            });
            candidateHandle = verification.candidateHandle;

            if (verification.ok) {
                candidateCacheRetired = true;
                addressCopy = {...addressCopy, candidateCacheRetired,
                    candidateCacheVerification: "fresh-readback-original"};
                await verboseLog("CLEANUP: cache readback prefix=" +
                    verification.freshPrefix.hex + " · alias=" +
                    verification.freshAlias.readbackHex);
                await log("Candidate cache readback passed on a fresh storage.");
            } else {
                candidateCloseSafe = false;
                retirementFailureReason =
                    "candidate-cache-verification-unconfirmed";
                addressCopy = {...addressCopy, candidateCacheRetired: false,
                    candidateCacheVerification: verification.stage};
                await verboseLog(formatInvalidationReadbackStatus(verification));
                await log("Candidate cache readback was not confirmed.");
            }
        } else {
            candidateCloseSafe = false;
            retirementFailureReason =
                "candidate-cache-invalidation-unconfirmed";
            addressCopy = {...addressCopy, candidateCacheRetired: false,
                candidateCacheVerification: "invalidation-unconfirmed"};
            await log("Candidate cache invalidation was not confirmed.");
        }
    }

    if (candidateHandle && candidateCloseSafe) {
        try {
            candidateCloseResult = Number(closeHandle(candidateHandle)) >>> 0;
            candidateHandle = 0;

            if (candidateCloseResult !== 0) {
                retirementFailureReason = "candidate-close-failed";
            }
        } catch (closeError) {
            candidateHandle = 0;
            retirementFailureReason = "candidate-close-threw: " +
                closeError.message;
        }
    } else if (candidateHandle) {
        retirementFailureReason = retirementFailureReason ||
            "candidate-close-skipped-unsafe-state";
    }

    return {ok: true, addressCopy, candidateCacheRetired, candidateHandle,
        workerStateSafe: stateSafe, workersQuiesced, candidateCloseResult,
        failureReason: retirementFailureReason};
}

/**
 * S22: delete save:/hole, invalidate the dirty file, then close every handle the
 * attempt still owns. A skipped or failed cleanup reports unsafe to retry.
 *
 * The legacy `ok` field is always true; `cleanupVerified` carries the real verdict.
 */
export async function cleanupScratchAndHandles({
    SCRATCH_DIR,
    auxiliaryStorageHandle,
    candidateCacheNeedsRetirement,
    candidateCacheRetired,
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
    workerStateSafe,
    keepDomainSessionOpen = false,
    dirtyFileSize = 0,
    dirtyFilePath = ""
}) {
    let cleanupAttempted = false;
    let cleanupDeleteTransport = null;
    let cleanupRemoveResult = null;
    let cleanupCommitTransport = null;
    let cleanupCommitResult = null;
    let cleanupHandlesClosed = 0;
    let cleanupExpectedHandles = 0;
    const cleanupCloseFailures = [];
    const cleanupErrors = [];
    const cleanupAllowed = workerStateSafe && (retainedEndpointActive ||
        !candidateCacheNeedsRetirement || candidateCacheRetired);
    let cleanupSkipReason = "worker-state-unsafe";

    if (workerStateSafe) {
        cleanupSkipReason = "candidate-cache-not-retired";
    }

    if (cleanupAllowed) {
        /*
         * One list drives both the expected count and the closing order, so the
         * verdict cannot drift away from what actually got closed.
         */
        const closeTargets = [];
        const addCloseTarget = (handle, label) => {
            if (handle) {
                closeTargets.push({handle, label});
            }
        };

        for (let cloneIndex = 0; cloneIndex < saveClones.length; cloneIndex++) {
            addCloseTarget(saveClones[cloneIndex], "save-clone-" + cloneIndex);
        }

        for (let cloneIndex = 0; cloneIndex < rootClones.length; cloneIndex++) {
            addCloseTarget(rootClones[cloneIndex], "root-clone-" + cloneIndex);
        }

        addCloseTarget(triggerHandle, "trigger");
        addCloseTarget(extentTriggerHandle, "extent-trigger");
        addCloseTarget(savedHandle, "save-fs");
        addCloseTarget(temporaryHandle, "temporary-fs");
        addCloseTarget(storageHandle, "storage");
        addCloseTarget(auxiliaryStorageHandle, "aux-storage");
        addCloseTarget(pinHandle, "pin");

        for (let storageIndex = 0; storageIndex < extraStorages.length; storageIndex++) {
            addCloseTarget(extraStorages[storageIndex], "extra-storage-" + storageIndex);
        }

        if (domainSession && !keepDomainSessionOpen) {
            addCloseTarget(domainSession.handle, "identity-domain-session");
        }

        addCloseTarget(rootSession, "fsp-session");
        cleanupExpectedHandles = closeTargets.length;
        cleanupAttempted = true;

        if (dirtyFileSize > 0 && dirtyFilePath) {
            let cacheInvalidateResult = null;

            try {
                cacheInvalidateResult = ipcFileInvalidate(savedHandle, dirtyFilePath, dirtyFileSize);
            } catch (error) {
                cacheInvalidateResult = "throw:" + String(error);
            }
            let resultText = cacheInvalidateResult;

            if (typeof cacheInvalidateResult === "number") {
                resultText = hex32(cacheInvalidateResult);
            }

            await verboseLog("CLEANUP: cache invalidate " + dirtyFilePath +
                " result=" + resultText);
        }

        try {
            const deleteStatus = ipcDeleteDirectoryRecursivelyChecked(savedHandle, SCRATCH_DIR);
            cleanupDeleteTransport = deleteStatus.transport;
            cleanupRemoveResult = deleteStatus.result;
        } catch (error) {
            cleanupErrors.push("delete=" + String(error));
        }
        try {
            const commitStatus = ipcCommitChecked(savedHandle);
            cleanupCommitTransport = commitStatus.transport;
            cleanupCommitResult = commitStatus.result;
        } catch (error) {
            cleanupErrors.push("commit=" + String(error));
        }

        const closeForCleanup = function(target) {
            try {
                const result = Number(closeHandle(target.handle)) >>> 0;

                if (result !== 0) {
                    cleanupCloseFailures.push(target.label + "=" + hex32(result));
                } else {
                    cleanupHandlesClosed++;
                }
            } catch (error) {
                cleanupCloseFailures.push(target.label + "=throw:" + String(error));
            }
        };

        for (let targetIndex = 0; targetIndex < closeTargets.length; targetIndex++) {
            closeForCleanup(closeTargets[targetIndex]);
        }

        if (!keepDomainSessionOpen) {
            domainSession = null;
        }
    }

    const cleanupOk = cleanupAttempted && cleanupDeleteTransport === 0 &&
        cleanupRemoveResult === 0 && cleanupCommitTransport === 0 &&
        cleanupCommitResult === 0 &&
        cleanupHandlesClosed === cleanupExpectedHandles &&
        cleanupCloseFailures.length === 0 && cleanupErrors.length === 0;
    let skipReason = cleanupSkipReason;

    if (cleanupAttempted) {
        skipReason = null;
    }

    return {
        /* Keep the legacy `ok` contract: this workflow reports `cleanupVerified` instead. */
        ok: true,
        cleanupVerified: cleanupOk,
        attempted: cleanupAttempted,
        skipped: !cleanupAttempted,
        workerStateSafe: Boolean(workerStateSafe),
        skipReason,
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

/**
 * Verify or remove /hole through the independent save handle, then close that
 * handle whatever happened. The fallback is skipped when cache retirement is
 * uncertain or workers are still active.
 */
export async function runHoleCleanupHandler(attemptState) {
    const cacheRetirementUnverified =
        attemptState.candidateCacheRetirementRequired &&
        !attemptState.cacheRetirementVerified &&
        !attemptState.retainedEndpointActive;

    if (cacheRetirementUnverified) {
        attemptState.holeAbsentVerified = false;
        attemptState.holeCleanupVerified = false;
        attemptState.safeToRetry = false;
        await log("Candidate cache retirement is unverified. Skipped /hole cleanup; hard reboot required.");
        await verboseLog("HOLE FALLBACK: skipped before filesystem IPC; the fallback save handle is left untouched until reboot.");
        return false;
    }

    const handle = attemptState.holeCleanupHandle;

    if (!handle) {
        attemptState.holeAbsentVerified = false;
        attemptState.holeCleanupVerified = false;
        await verboseLog("HOLE FALLBACK: no independent save handle; absence cannot be verified.");
        return false;
    }

    const fallback = {
        initial: null,
        deletion: null,
        commit: null,
        verification: null,
        reason: null,
        shouldVerify: false,
        closeResult: null,
        absenceVerifiedByPrimary: false
    };

    try {
        await verboseLog("HOLE FALLBACK: checking /hole on the reserved temporary save handle.");

        if (!attemptState.workersQuiesced) {
            fallback.reason = "workers-not-quiesced";

        } else if (attemptState.primaryScratchCleanupVerified) {
            fallback.absenceVerifiedByPrimary = true;

        } else {
            fallback.initial = readEntryTypeChecked(handle, FALLBACK_HOLE_PATH);

            if (fallback.initial.transport !== 0) {
                fallback.reason = "initial-check-transport=" +
                    formatCode(fallback.initial.transport);

            } else if (fallback.initial.result === ENTRY_NOT_FOUND) {
                if (!attemptState.primaryCommitVerified) {
                    fallback.commit = ipcCommitChecked(handle);

                    if (fallback.commit.transport !== 0 || fallback.commit.result !== 0) {
                        fallback.reason = "recommit-failed";
                    } else {
                        fallback.verification = readEntryTypeChecked(handle, FALLBACK_HOLE_PATH);

                        if (fallback.verification.transport !== 0 ||
                            fallback.verification.result !== ENTRY_NOT_FOUND) {
                            fallback.reason = "absence-verification-failed-after-recommit";
                        }
                    }
                } else {
                    fallback.verification = fallback.initial;
                }

                fallback.shouldVerify = !fallback.reason && Boolean(fallback.verification);

            } else if (fallback.initial.result === 0 && fallback.initial.type === 0) {
                fallback.deletion = ipcDeleteDirectoryRecursivelyChecked(handle, FALLBACK_HOLE_PATH);

                if (fallback.deletion.transport !== 0 || fallback.deletion.result !== 0) {
                    fallback.reason = "delete-failed";
                } else {
                    fallback.commit = ipcCommitChecked(handle);

                    if (fallback.commit.transport !== 0 || fallback.commit.result !== 0) {
                        fallback.reason = "commit-failed";
                    } else {
                        fallback.shouldVerify = true;
                    }
                }

            } else if (fallback.initial.result === 0) {
                fallback.reason = "path-exists-but-is-not-a-directory";

            } else {
                fallback.reason = "initial-check-result=" + formatCode(fallback.initial.result);
            }

            if (fallback.shouldVerify && !fallback.verification) {
                fallback.verification = readEntryTypeChecked(handle, FALLBACK_HOLE_PATH);

                if (fallback.verification.transport !== 0 ||
                    fallback.verification.result !== ENTRY_NOT_FOUND) {
                    fallback.reason = "absence-verification-failed";
                }
            }
        }
    } catch (error) {
        fallback.reason = "handler-threw:" + String(error?.message || error);
    } finally {
        attemptState.holeAbsentVerified = Boolean(!fallback.reason &&
            (fallback.absenceVerifiedByPrimary ||
                (fallback.shouldVerify &&
                    fallback.verification?.transport === 0 &&
                    fallback.verification?.result === ENTRY_NOT_FOUND)));
        try {
            fallback.closeResult = Number(closeHandle(handle)) >>> 0;
        } catch (error) {
            fallback.reason = fallback.reason || "handle-close-threw:" +
                String(error?.message || error);
        }
        attemptState.holeCleanupHandle = 0;
    }

    attemptState.holeCleanupVerified = Boolean(attemptState.holeAbsentVerified &&
        fallback.closeResult === 0);

    if (isFallbackHoleCleanupComplete(attemptState)) {
        attemptState.cleanupVerified = true;
    }

    await verboseLog(formatHoleFallbackSummary(attemptState, fallback));

    return attemptState.holeCleanupVerified;
}

function describeInitialHoleEntry(fallback) {
    if (fallback.absenceVerifiedByPrimary) {
        return "primary-cleanup-verified";
    }

    if (fallback.initial?.transport !== 0) {
        return "transport=" + formatCode(fallback.initial?.transport);
    }

    if (fallback.initial?.result === ENTRY_NOT_FOUND) {
        return "already-absent";
    }

    if (fallback.initial?.result === 0) {
        return "present-type=" + fallback.initial.type;
    }

    return "result=" + formatCode(fallback.initial?.result);
}

function describeFallbackCommit(attemptState, commit) {
    if (commit) {
        return formatCode(commit.transport) + "/" + formatCode(commit.result);
    }

    if (attemptState.primaryCommitVerified) {
        return "primary-verified";
    }

    return "not-needed";
}

function formatHoleFallbackSummary(attemptState, fallback) {
    const initialText = describeInitialHoleEntry(fallback);
    const commitText = describeFallbackCommit(attemptState, fallback.commit);
    let deletionText = "not-needed";

    if (fallback.deletion) {
        deletionText = formatCode(fallback.deletion.transport) + "/" +
            formatCode(fallback.deletion.result);
    }

    let fallbackIpc = "used";

    if (fallback.absenceVerifiedByPrimary) {
        fallbackIpc = "skipped";
    }

    let absence = "no";

    if (attemptState.holeAbsentVerified) {
        absence = "verified";
    }

    let reasonText = "";

    if (fallback.reason) {
        reasonText = "; reason=" + fallback.reason;
    }

    return "HOLE FALLBACK: initial=" + initialText + "; delete=" + deletionText +
        "; commit=" + commitText + "; fallbackIpc=" + fallbackIpc +
        "; absent=" + absence +
        "; handleClose=" + formatCode(fallback.closeResult) + reasonText + ".";
}

function formatInvalidationReadbackStatus(verification) {
    let message = "CLEANUP: cache readback=" + verification.stage;

    if (verification.freshAlias?.state) {
        message += " · alias=" + verification.freshAlias.state;
    }

    if (verification.detail) {
        message += " · " + verification.detail;
    }

    return message;
}

function isFallbackHoleCleanupComplete(attemptState) {
    return !attemptState.cleanupVerified &&
        attemptState.holeCleanupVerified &&
        attemptState.primaryCleanupAttempted &&
        attemptState.primaryHandlesClosed &&
        attemptState.endpointRetirementVerified &&
        attemptState.workerStateSafe;
}

/*
 * The recovery instruction has to read the same wherever cleanup reports an unsafe
 * state, so the user gets one action from every failure path.
 */
export function formatUnsafeState(reason) {
    const detail = String(reason || "retained endpoint may be active")
        .replace(/[.!]+$/, "");
    return "STATE IS UNSAFE - " + detail + ". Do not close the game or reboot normally; hard reboot now (hold Power for 15 seconds).";
}

function readStorageHex(storageHandle, offset, helpers) {
    try {
        const buffer = allocPage(0x1000);
        call_rop(GADGET_MEMSET, buffer, 0xA5n, 16n);
        const read = ipcStorageRead(storageHandle, offset, 16, buffer);

        if (!read || read.error !== 0) {
            return {ok: false, error: read?.error ?? null,
                transport: read?.transport ?? null};
        }

        return {ok: true, error: read.error, transport: read.transport,
            hex: helpers.readHexBytes(buffer, 16)};
    } catch (error) {
        return {ok: false, error: null, transport: null,
            detail: String(error?.message || error)};
    }
}

/**
 * After invalidation, confirm that a fresh handle reads the original bytes and the
 * cache alias. The result carries any handle that could not be closed, so callers
 * never assume it was released.
 */
async function verifyInvalidatedCandidateCache({
    candidateHandle,
    helpers,
    addressCopy,
    rootSession
}) {
    const expectedPrefix = addressCopy?.primeHex;
    const expectedAlias = addressCopy?.aliasControlHex;
    const aliasOffset = addressCopy?.config?.ALIAS_OFFSET;
    const hasBaseline = typeof expectedPrefix === "string" &&
        /^[0-9a-f]{32}$/i.test(expectedPrefix) &&
        typeof expectedAlias === "string" &&
        /^[0-9a-f]{32}$/i.test(expectedAlias) &&
        expectedPrefix !== expectedAlias &&
        Number.isSafeInteger(aliasOffset) && aliasOffset >= 0 &&
        rootSession && typeof helpers?.inspectCandidateCacheAlias === "function";

    if (!hasBaseline) {
        return {ok: false, candidateHandle,
            stage: "verification-baseline-unavailable"};
    }

    const candidatePrefix = readStorageHex(candidateHandle, 0, helpers);

    if (!candidatePrefix.ok || candidatePrefix.hex !== expectedPrefix) {
        return {ok: false, candidateHandle,
            stage: "candidate-prefix-mismatch", candidatePrefix};
    }

    let candidateCloseResult = null;
    try {
        candidateCloseResult = Number(closeHandle(candidateHandle)) >>> 0;
    } catch (error) {
        return {ok: false, candidateHandle,
            stage: "candidate-close-failed",
            detail: String(error?.message || error)};
    }

    if (candidateCloseResult !== 0) {
        return {ok: false, candidateHandle,
            stage: "candidate-close-failed", candidateCloseResult};
    }

    let freshHandle = 0;
    try {
        freshHandle = Number(openContentStorage(rootSession)) >>> 0;
    } catch (error) {
        return {ok: false, candidateHandle: 0,
            stage: "fresh-storage-open-failed",
            detail: String(error?.message || error)};
    }

    if (!freshHandle) {
        return {ok: false, candidateHandle: 0,
            stage: "fresh-storage-open-failed"};
    }

    let freshReadback = null;
    let freshCloseResult = null;
    let freshCloseError = null;
    try {
        const freshPrefix = readStorageHex(freshHandle, 0, helpers);
        let freshAlias = null;
        try {
            freshAlias = helpers.inspectCandidateCacheAlias(freshHandle, addressCopy);
        } catch (error) {
            freshAlias = {state: "unavailable",
                detail: String(error?.message || error)};
        }

        const readbackMatches = freshPrefix.ok &&
            freshPrefix.hex === expectedPrefix &&
            freshAlias?.state === "original";

        if (readbackMatches) {
            freshReadback = {ok: true, freshPrefix, freshAlias};
        } else {
            freshReadback = {ok: false, stage: "fresh-storage-readback-mismatch",
                freshPrefix, freshAlias};
        }
    } catch (error) {
        freshReadback = {ok: false, stage: "fresh-storage-readback-threw",
            detail: String(error?.message || error)};
    } finally {
        try {
            freshCloseResult = Number(closeHandle(freshHandle)) >>> 0;
        } catch (error) {
            freshCloseError = String(error?.message || error);
        }
    }

    if (freshCloseError || freshCloseResult !== 0) {
        return {ok: false, candidateHandle: freshHandle,
            stage: "fresh-storage-close-failed", freshReadback,
            freshCloseResult, detail: freshCloseError};
    }

    if (!freshReadback.ok) {
        return {...freshReadback, candidateHandle: 0};
    }

    return {ok: true, candidateHandle: 0, candidatePrefix,
        freshPrefix: freshReadback.freshPrefix,
        freshAlias: freshReadback.freshAlias};
}

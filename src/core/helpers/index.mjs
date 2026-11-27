import {
    buffersEqual,
    checkAddressHeaderEncoding,
    cleanup,
    hasByteDifferent,
    hasByteDifferentFast,
    ipcGetEntryTypeRawBytes,
    readFsAddressBytes,
    readHexBytes,
    bytesToHex,
    scanPointerWords
} from "./util.mjs";

import {
    inspectFspIdentityTargetsReadOnly as _inspectFspIdentityTargetsReadOnly,
    scanNativeLinkBuffer,
    scanRootDomainChunk,
    scanRootDomainChunkPrefiltered,
    captureDomainTail,
    recordRootDomainCandidate,
    inspectRootBackend
} from "./scan.mjs";

import {
    resolvePoolCandidates,
    discoverMetadataAnchors,
    qualifyMetadataPage,
    verifyAddressCandidate
} from "./metadata-discovery.mjs";

import {
    inspectCandidateCacheAlias,
    installAddressHeader,
    qualifyCacheBucketPeriod
} from "./cache.mjs";

import {
    buildPlans,
    configureProfile,
    configurePayload,
    writeIntoPayload,
    checkPathPairQuiet,
    captureRenameInputState,
    queryCanaryHealth,
    nulWrites,
    analyzeWave
} from "./wave.mjs";

/**
 * Build the helper surface the pipeline steps receive. The two options decide how
 * much the root identity scan measures; everything else is a plain re-export, so a
 * step never has to import a helper module directly.
 */
export function createFspIdentityHelpers(options = {}) {
    const optimizeRootCandidateScan =
        options.optimizeRootCandidateScan === true;
    const collectRootScanTiming = options.collectRootScanTiming === true;

    return {
        inspectFspIdentityTargetsReadOnly: (input) =>
            _inspectFspIdentityTargetsReadOnly({
                ...input, optimizeRootCandidateScan, collectRootScanTiming
            }),
        scanNativeLinkBuffer,
        resolvePoolCandidates,
        discoverMetadataAnchors,
        qualifyMetadataPage,
        verifyAddressCandidate,
        scanRootDomainChunk,
        scanRootDomainChunkPrefiltered,
        captureDomainTail,
        recordRootDomainCandidate,
        readFsAddressBytes,
        inspectRootBackend,
        readHexBytes,
        bytesToHex,
        ipcGetEntryTypeRawBytes,
        checkAddressHeaderEncoding,
        buffersEqual,
        hasByteDifferent,
        hasByteDifferentFast,
        scanPointerWords,
        cleanup,
        inspectCandidateCacheAlias,
        installAddressHeader,
        qualifyCacheBucketPeriod,
        buildPlans,
        configureProfile,
        configurePayload,
        writeIntoPayload,
        checkPathPairQuiet,
        captureRenameInputState,
        queryCanaryHealth,
        nulWrites,
        analyzeWave
    };
}

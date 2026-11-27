/**
 * Parse an SFCO response, HIPC handles, descriptors and alignment included.
 *
 * @param {bigint} buf Address of the IPC buffer.
 * @returns {{at: number, result: number, data: number, copies: number[], moves: number[]}}
 */
function cmifReply(buf) {
    const U32 = (o) => Number(read32(buf + BigInt(o))) >>> 0;
    const t0 = U32(0), t1 = U32(4);
    let at = 8;
    const copies = [], moves = [];

    if ((t1 >>> 31) !== 0) {
        const sp = U32(8); at = 12;

        if (sp & 1) {
            at += 8;
        }

        let n = (sp >>> 1) & 15;
        for (let i = 0; i < n; i++) {
            copies.push(U32(at + 4 * i));
        }
        at += n * 4;
        n = (sp >>> 5) & 15;
        for (let i = 0; i < n; i++) {
            moves.push(U32(at + 4 * i));
        }
        at += n * 4;
    }

    at += (t0 >>> 16 & 15) * 8;
    at += ((t0 >>> 20 & 15) + (t0 >>> 24 & 15) + (t0 >>> 28 & 15)) * 12;
    at = (at + 15) & ~15;
    return { at, result: U32(at + 8), data: at + 16, copies, moves };
}

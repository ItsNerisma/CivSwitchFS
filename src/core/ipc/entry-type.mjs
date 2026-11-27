import coreRuntime from "../runtime.mjs";

const {
    allocPage,
    cmifReply,
    prepPacket,
    read32,
    sendIPC,
    write32,
    writeStr,
    writeXDesc
} = coreRuntime;

const SFCI_MAGIC = 0x49434653n;
const GET_ENTRY_TYPE_COMMAND = 7n;

/**
 * Read an entry type, keeping HIPC transport failures separate from filesystem
 * errors.
 *
 * @returns {{transport: number, result: number | null, type: number | null}}
 */
export function readEntryTypeChecked(handle, path) {
    const pathBuffer = allocPage(0x1000);
    const request = allocPage(0x2000);

    writeStr(pathBuffer, path);
    prepPacket(request, (4 | (1 << 16)) >>> 0, 8, []);
    writeXDesc(request, 8, pathBuffer, path.length + 1);
    write32(request + 0x10n, SFCI_MAGIC);
    write32(request + 0x18n, GET_ENTRY_TYPE_COMMAND);

    const transport = Number(sendIPC(handle, request)) >>> 0;

    if (transport !== 0) {
        return {transport, result: null, type: null};
    }

    const reply = cmifReply(request);
    let entryType = null;

    if (reply.result === 0) {
        entryType = Number(read32(request + BigInt(reply.data))) >>> 0;
    }

    return {
        transport,
        result: reply.result,
        type: entryType
    };
}

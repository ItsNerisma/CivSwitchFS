// Frame layout and result reader shared with the raw worker frames that threads.js builds.

const FRAME_STEP = 0x140;
const FRAME_RESULT = 0x800;
const FRAME_SENTINEL = 0xfedcba9876543210n;

function _frameAlignPage(n) {
    return Math.ceil(n / 0x1000) * 0x1000;
}

function _frameGetArg(call, k) {
    var a = call.args[k];
    return (a === undefined || a === null) ? 0n : BigInt(a);
}

// Read step i's result out of a frame: a BigInt, or SENTINEL when the step has not finished.
function readFrameResult(frame, i) {
    return read64(frame + BigInt(FRAME_RESULT + i * 8));
}

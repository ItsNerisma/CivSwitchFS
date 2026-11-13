# CivSwitchFS

FS identity-promotion research payload for **Civilization VII** on Nintendo
Switch, built on the CivSwitch Remote JS Loader.

The payload temporarily promotes the `fsp-srv` filesystem identity to PID `1`,
opens the User content storage, lists `/`, restores the original objects, and
cleans up. It is a proof of elevated filesystem access, not a permanent
modification and not a NAND/BIS tool.

> **Research and education only. Use your own hardware.**
> This payload is **HIGH risk**: it creates temporary files, writes up to
> 8 MiB of dirty data per wave, modifies `fsp-srv` memory, and retries up to
> 10 times. Use a disposable save and back up anything you care about. It can
> crash or wedge the FS service; a reboot may be required.

## Status

Tested configuration:

- Nintendo Switch 2, firmware **23.0.1**
- Civilization VII **1.0.0**, physical cartridge
- CivSwitch Remote JS Loader already running

Success is **stochastic**. A qualified timing window does not guarantee a
canary flip. In the research runs, one payload succeeded on its third campaign;
three later full sends reached the 10-attempt cap with clean cleanup. The
payload is intentionally bounded and stops after ten attempts.

## Requirements

- A console running the CivSwitch Remote JS Loader, reachable over the network.
- Node.js 20 or newer on the host.
- A disposable Civilization VII save. The payload writes to `save:/hole` and
  removes it during cleanup.
- No additional npm runtime dependencies; `esbuild` is only used to build.

## Quick start

```sh
npm install
npm run check
npm run build
npm run send -- <console-ip>
```

`npm run send` uses port `9026` by default. To choose another port or entry:

```sh
node tools/send.mjs <console-ip> <port> [entry]
```

The build writes `dist/core.js` and prints its SHA256. The generated file is
the single classic script sent to the loader; `dist/` is gitignored.

## What the payload does

1. Acquires a cache alias in `fsp-srv` through the reserved-gap timing window.
2. Discovers and verifies the current root, NCA, and save identity objects.
3. Installs the retained two-bucket memory endpoint and verifies pointer
   readback plus a scratch write/read/restore.
4. Temporarily writes PID `1` to the three verified identity fields.
5. Makes one elevated `OpenContentStorageFileSystem(User=1)` call
   (`fsp-srv` cmd 110), lists `/`, and closes the returned handles.
6. Restores the exact original objects in reverse order.
7. Retires the endpoint and removes the temporary `save:/hole` tree.

Each campaign starts from fresh discovery. No prior-run address or PID is used
as a lookup input. The elevated call runs only after all three PID fields read
back as `1`. No BIS command is issued: the `User=1` selector is a storage ID,
not the forged process PID.

## Reading the logs

A successful permission proof contains lines similar to:

```text
A03/10 Permission proof: User content-storage opened and / listed successfully; PID restoration=verified.
A03/10 SUCCESS: User content-storage root listing verified; PID restoration, endpoint retirement, save cleanup, independent /hole verification, handle closure, and tracked frees all passed.
```

The final `Executed successfully` line only means the script returned; it is
not a permission proof. Treat the `SUCCESS` line and the cleanup details as the
result.

A bounded run can also end with:

```text
CAP: no User content-storage proof after 10 attempts; last cleanup was verified.
```

That is a clean stop, not a crash. Do not immediately rerun a save-writing
campaign without reviewing the save health and restarting if cleanup was not
verified.

## Recovery and safety

- Use a **disposable save**. Repeated 8 MiB scratch writes and commits can
  degrade save-FS health.
- If cleanup, PID restoration, or endpoint retirement is not verified, restart
  the console before running the payload again.
- If the console wedges, reboot it and inspect the save before another run.
- Do not run this against a console whose data you cannot lose.
- The payload does not access BIS, PRODINFO, keys, tickets, or NAND. Do not
  extend it to destructive operations.
- Only run this on hardware you own. Do not distribute Nintendo firmware, game
  files, saves, or keys with this repository.

## Architecture

```text
src/core.js                 payload entry, retry supervisor, and logging
src/core/config.mjs         tuning constants and role schedules
src/core/steps.mjs          acquisition, discovery, alias, address, cleanup
src/core/helpers.mjs        capture, scan, qualification, and wave analysis
src/core/promotion.mjs      PID promotion, User storage call, restoration
src/core/runtime.mjs        bridge to the injected CivSwitch core API
src/core/*.js               classic core helpers injected by the bundler
src/core/analysis/          byte, cache-plan, and root-layout helpers
src/core/ipc/               HIPC, domain, filesystem, storage, wave helpers
tools/bundle.mjs            core concatenation + esbuild + loader wrapper
tools/build.mjs             write dist/core.js
tools/send.mjs              build and send over TCP
tools/check.mjs             syntax and bundle-size check
```

The core files are classic scripts because the loader evaluates one script and
the helpers share its global scope. The payload entry and its modules are ESM
and are bundled by `tools/bundle.mjs`. This split is intentional; the core
layout may be reorganized later without changing the payload behavior.

## How it works

The full research narrative is in [HOW_IT_WORKS.md](HOW_IT_WORKS.md). It starts
after the initial CivSwitch userland exploit and explains the path from game
code execution to `fsp-srv`, including the reserved-gap race, cache alias,
identity discovery, and promotion. References to numbered "Try" experiments are
historical and point back to the research repository.

## License and provenance

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
The payload builds on the MIT-licensed CivSwitch loader by Gezine and the
ns2jb CivSwitch port by Slapah; no third-party source tree is vendored here.

This project is not affiliated with or endorsed by Nintendo. It contains no
Nintendo firmware, game files, keys, tickets, or save data.

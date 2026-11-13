# CivSwitchFS

> [!IMPORTANT]
> Thanks to **Slapah** for the ns2jb filesystem port to CivSwitch and **Kurumuz** for the improved fork of ns2jb from **Pepspiu**, which laid the groundwork for this research. ** All kudos goes to them for the Civ FS port :heart:

This is payload provides **access to FS privileges** through an elevated fsp-srv handle. It runs inside the **CivSwitch Remote JS Loader**. That elevated session is exposed as `globalThis.fspSrv` for the next payloads. **IT'S ALSO TARGETTING DEVS**, *not normies I'm sorry but you probably won't know what to do with this !*.

> [!NOTE]
> CivSwitchFS is **semi-untethered**, RPC was fully removed

## Tested configuration

- Nintendo Switch 2, firmware **23.0.1**
- **Civilization VII 1.0.0**, physical cartridge
- CivSwitch Remote JS Loader already running

## Requirements

- Node.js **20 or later** and npm
- A Switch 2 with the CivSwitch Remote JS Loader already running and reachable
  on the local network when installing persistence or sending a payload

## Usage

Install dependencies once from this repository:

~~~sh
npm install
~~~

### Persist the payload (optionnal)

With the CivSwitch Remote JS Loader running, install the persistent image:

~~~sh
npm run persist:install -- <console-ip> [--minify-payload]
~~~

Future launches from that save start the exploit, loader, and
payload automatically, without a computer or network connection. 

The persisted payload removes whitespace and comments by default while keeping
source names and syntax. Pass `--debug-payload` to preserve formatting, or
`--minify-payload` to also shorten ESM local identifiers.

The installer does not back up the old save. 

### Launch the exploit

If you are not going for persistence, just start the CivSwitch Remote JS Loader
using your usual CivSwitch setup. Then send the payload 

~~~sh
npm run send -- <console-ip>
~~~

Wait for **`You just Civ Sevened your machine, congrats`** which obviously means success :tada: !
Then, the loader automatically shows `Awaiting payload at <ip>:9026` and you are free to send payloads.

### Booting faster next time (this will be automatised eventually)

After success, the payload prints the working `roleDelays` and `guardDelays`
values in nanoseconds. To use them as the starting schedule next time, replace
the arrays in [`src/core/config.mjs`](src/core/config.mjs#L44-L47):

~~~js
var roleDelays = [0, 300000, 350000, 450000, 550000, 650000, 1000000, 1200000, 1300000, 1700000];
var guardDelays = [150000, 300000];
~~~

The trigger's initial sleep is 1,600,000 ns. The Slapah/Kurumuz
reference schedule used role delays
`[0, 300000, 350000, 450000, 550000, 650000, 1700000, 2000000, 2150000, 2800000]`,
guard delays `[0, 150000]`, and an initial trigger sleep of 2,400,000 ns.

Use the values printed by your successful run in place of the example values.
If you use the persisted payload, run the installer again so its saved image includes the new timings.

> [!NOTE]
> You can play with the delays in `src/core/config.mjs`, try some combinaisons !
[WIP] This will eventually be saved in the save partition to be retrieved, but that's for another day !

## Example FS usage

After the main payload reports success, you can send follow-up payloads and use
the `globalThis.fspSrv` handle to perform filesystem operations.

An example can be found in `examples/user-storage`.

## Notes

- The auto timing calibration is not perfect yet, some freezes can happen
- THERE IS SO MUCH MORE to be done, I'm just releasing now so you guys can study the semi-untethered stuff

## Project structure

```text
src/core.js          # payload entry point and flow
src/core/            # steps, memory access, and FS communication
src/core/config.mjs  # the whole exploit conf, tweak it if you want
examples/            # small payload usage examples
persist/             # persistence builder inputs, save codec, writer, and installer
tools/               # well, tools
```

## License

The original code in this repository is distributed under the MIT license. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for detailed notices and credits.

For technical details, see [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

This project is not affiliated with or endorsed by Nintendo. It contains no Nintendo firmware, keys, tickets, or personal saves; `persist/save_template.bin` is the pristine trigger template used by the installer.

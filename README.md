# CivSwitchFS

> [!IMPORTANT]
> Thanks to [**Slapah**](https://github.com/byizmysh/IZCIVSwitch/blob/main/NOTICE.md#upstream) for the ns2jb filesystem port to CivSwitch and [**Kurumuz**](https://gitlab.com/kurumuz/ns2jb) for the improved fork of ns2jb from [**pepsipu**](https://gitlab.com/pepsipu/ns2jb), which laid the groundwork for this research. All kudos goes to them for the Civ FS port :heart:. Big thanks to Alula for giving really cool insights about making the FS acquisition more reliable, really goated !
>
> If you are looking for a reliable semi-untethered KaiHEN access, this fork [CivSwitchFS-kaiHEN](https://github.com/s8n/CivSwitchFS-kaiHEN) from [@Ave](https://github.com/aveao) is the way to go.

This is payload provides **access to FS privileges** through an elevated fsp-srv handle. It runs inside the **CivSwitch Remote JS Loader**. That elevated session is exposed as `globalThis.fspSrv` for the next payloads.

## A bit of a preface

Smol demo (updated) https://streamable.com/wtcdnk

CivSwitchFS is **semi-untethered**, RPC was fully removed :tada: ! It should also be more consistent for any hardware.

**It's intended for devs**, as all I give is a god `fsp-srv` handle (full FS) for you to play with. The rest is for you to figure out.

> [!IMPORTANT]
> Beware that this FS exploit is not 100% safe, it could corrupt your save, cache or worse. We had 2 bricks on forks using that FS acquisition as a base. 

### Tested configuration

- Nintendo Switch 2, firmware **23.0.1**
- **Civilization VII 1.0.0**, physical cartridge
- CivSwitch Remote JS Loader already running

### Requirements

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
npm run persist -- <console-ip> [--minify-payload]
~~~

Future launches from that save start the exploit, loader, and
payload automatically, without a computer or network connection. 

The installer does not back up the old save. 

### Launch the exploit

If you are not going for persistence, just start the CivSwitch Remote JS Loader
using your usual CivSwitch setup. Then send the payload 

~~~sh
npm run send -- <console-ip>
~~~

Wait for **`You just Civ Sevened your machine, congrats`** which obviously means success :tada: !
Then, the loader automatically shows `Awaiting payload at <ip>:9026` and you are free to send payloads.

### Timing calibration

Without a valid saved timing file, the payload starts with this schedule, in nanoseconds:

~~~js
var roleDelays = [0, 300000, 350000, 450000, 550000, 650000, 1000000, 1200000, 1300000, 1700000];
var guardDelays = [150000, 300000];
~~~

> [!NOTE]
> If timings were adjusted during a successful run, they will be saved under `save:/civswitchfs/timings.json` and will be reused the next time the exploit is beeing executed.

### Controls

- **X**: restore the original timings (starting next attempt, will also delete the config file at the end)
- **B**: stops after the current wave clean up
- **Y**: toggle between normal and verbose summaries

## Example FS usage

After the main payload reports success, you can send follow-up payloads and use
the `globalThis.fspSrv` handle to perform filesystem operations.

An example can be found in `examples/user-storage`.

## Notes

- I've let my bench mode and worker easy configuration in there, feel free to play with it
- You can learn about how the exploit works [there](https://github.com/ItsNerisma/CivSwitchFS/blob/main/HOW_IT_WORKS.md)

## Project structure

```text
src/core.js          # payload entry point and flow
src/core/            # steps, memory access, and FS communication
src/core/config.mjs  # the whole exploit conf, tweak it if you want
examples/            # small payload usage examples
persist/             # persistence builder inputs, save codec, writer, and installer
tools/               # well, tools
```

## Credits

- **[Gezine/CivSwitch](https://github.com/Gezine/CivSwitch)**: userland exploit and persistent installer
- **[pepsipu/ns2jb](https://gitlab.com/pepsipu/ns2jb)**: og FS exploit
- **Slapah/CivSwitch**: first true working ns2jb port for Civ. Sadly after his code beeing stole, he chose to nuke it.
- **[Kurumuz/ns2jb](https://gitlab.com/kurumuz/ns2jb)**: improved version of ns2jb
- **Alula**: improved FS acquisition advices
- **Ave**: listened to all of my shit for days


## License

The original code in this repository is distributed under the MIT license. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for detailed notices and credits.

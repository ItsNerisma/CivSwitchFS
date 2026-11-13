# How the fsp-srv Permission-Promotion Path Works

> This document starts **after** the initial userland exploit (CivSwitch) and
> explains the path from game-process code execution to fsp-srv. It separates
> verified project results from reference details that remain unverified here.

> **Payload status:** the shipped payload implements the final chain. It
> temporarily promotes the fsp-srv root, NCA, and save identity PIDs to `1`,
> opens User content storage, lists `/`, restores the original objects, and
> cleans up. The System BIS listing used during the research was removed.
> Success is stochastic: the payload retries up to 10 campaigns, and a
> qualified timing window does not guarantee a canary flip.
>
> **Naming note:** "Try N" below refers to the historical numbered experiments
> from the research repository. The current payload is the consolidated
> version of the final chain.

Throughout this document, **Verified** means observed in this project or
confirmed by local static analysis; **Reference model** means described by
ns2jb/Kurumuz or Slapah but not yet independently demonstrated here;
**Unknown** marks the remaining gap.

---

## Table of Contents

1. [The Big Picture](#1-the-big-picture)
2. [What We Start With](#2-what-we-start-with)
3. [Step 1 — Talk to fsp-srv](#3-step-1--talk-to-fsp-srv)
4. [Step 2 — Discover Your Permissions](#4-step-2--discover-your-permissions)
5. [Step 3 — The Permission Boundary](#5-step-3--the-permission-boundary)
6. [Step 4 — The Reference Idea: Corrupt fsp-srv's Memory](#6-step-4--the-reference-idea-corrupt-fsp-srvs-memory)
7. [Step 5 — Reference Model: Path Normalization and Heap Corruption](#7-step-5--reference-model-path-normalization-and-heap-corruption)
8. [Step 6 — Reserved-Gap Race and ARW Hypothesis](#8-step-6--reserved-gap-race-and-arw-hypothesis)
9. [Step 7 — Try 009: Controlled Race and Canary Redirect](#9-step-7--try-009-controlled-race-and-canary-redirect)
10. [Step 8 — Try 010: Candidate IStorage Baseline](#10-step-8--try-010-candidate-istorage-baseline)
11. [Step 9 — Try 011: Cache Alias Confirmed](#11-step-9--try-011-cache-alias-confirmed)
12. [Step 10 — Try 012–014: Widened Read and Heap Pointer Leak](#12-step-10--try-012014-widened-read-and-heap-pointer-leak)
13. [Step 11 — Try18–25: Metadata, Root Identity, and Permission Promotion](#13-step-11--try1825-metadata-root-identity-and-permission-promotion)
14. [Current Status of the Chain](#14-current-status-of-the-chain)
15. [Glossary](#15-glossary)

---

## 1. The Big Picture

The Nintendo Switch runs **Horizon OS**, a microkernel where every system
service runs in its own isolated process. The filesystem service is called
**fsp-srv**. Games talk to it through **IPC** (Inter-Process Communication) —
think of it as calling a remote API, except the "server" is another process
on the same machine.

**Verified milestone:** Try25 demonstrated broader fsp-srv permissions by
temporarily changing the PID fields stored in the server-side root and backend
objects for the current session. The actual game process PID and kernel-provided
IPC PID were not changed. Exact PID restoration was observed in a run; see F68.

**Verified constraint:** for `SetCurrentProcess`, the kernel supplies the real
PID through the IPC special header and the server-side framework replaces any
client-provided PID with that value. A client-side forged PID therefore does
not work (F14).

**Verified progress:** a client cannot forge the PID in the IPC special header
(F14), but Try25 used the retained memory endpoint to update the already
registered fsp-srv identity objects. After promotion, the User content-storage
open and listing succeeded; one run also listed the System BIS root (F69).
The payload keeps only the User content-storage check. The earlier stages
remain the foundation: Try 009 reached a canary redirect, Try 010 established
the candidate baseline, and Try 011 **confirmed the cache alias** (F49–F51).

```
┌─────────────┐         IPC          ┌─────────────┐
│  Game        │ ──── messages ────── │  fsp-srv     │
│  (our code)  │                      │  (FS server) │
│              │   kernel writes      │              │
│ PID = game   │   real PID ───────── │ stored: game │
│              │                      │              │
│ retained     │  memory endpoint     │ stored: 1    │ ← temporary Try25 state
│ memory write │──────────────────────│──────────────│
└─────────────┘                       └─────────────┘
```

---

## 2. What We Start With

After the userland exploit, we have:

| Capability | What it means |
|---|---|
| **Arbitrary Read/Write** | Read and write any address in the game's own memory |
| **ROP / function calls** | Call any function in the game's SDK library |
| **TCP connection** | Send JavaScript payloads from a PC, get results back |

At the start of the chain, we did **not** have:
- Access to other processes' memory (fsp-srv, the kernel)
- Any elevated permissions
- The ability to change what the kernel writes into IPC messages

Try25 later demonstrated temporary elevation **inside fsp-srv's permission
checks** by changing server-side identity fields. It did not grant access to
kernel memory or change the game's actual process PID.

The game uses the standard Nintendo SDK. This SDK contains all the IPC
plumbing to talk to system services. We can reuse it.

---

## 3. Step 1 — Talk to fsp-srv

The game already has filesystem handles. For controlled experiments, Try 009
opens an independent fsp-srv root session and separately clones the mounted
`save` filesystem twice. Those two save clients let the test route marker
creation and extent-trigger requests the same way as the reference. A fresh
reservation session is opened for each wave. This gives the try distinct
handles for its roles; it does not grant extra permissions.

### 3.1 — Connect to the Service Manager

The Service Manager (sm:) is the phone book of Horizon OS. Every service
registers its name there. We call:

```
SM_Initialize()           → connect to sm:
SM_GetService("fsp-srv")  → get a new session handle
SM_Finalize()             → disconnect from sm:
```

This gives us an IPC handle to fsp-srv. The sequence was exercised in earlier
probes and is reused by Try 009.

### 3.2 — Register our process

fsp-srv requires every client to announce itself:

```
SetCurrentProcess (cmd 1, with PID in special header)
```

> **Verified:** the kernel supplies the real PID for this registration
> (F14). Try 009 did not change the stored value. Try25 later changed the
> server-side identity objects after registration; it did not alter this
> kernel-provided PID (F68–F69).

### 3.3 — Convert to domain mode

IPC supports two modes: **session** and **domain**. Domain mode multiplexes
multiple "sub-objects" (like interfaces) over a single session handle.
fsp-srv requires domain mode for most useful commands.

```
ConvertToDomain (Control cmd 0) → returns a root domain object ID
```

> **Analogy:** session mode is like opening one TCP connection per request.
> Domain mode is like HTTP/2 multiplexing — one connection, many streams.
> Each "stream" has an object ID.

After this, we can issue domain commands that target filesystem objects
(`IFileSystem`, `IFile`, `IStorage`, and others). Try 009 also uses the mounted
`save` filesystem objects directly for save operations; it does not route every
role through the independent root session.

---

## 4. Step 2 — Discover Your Permissions

Every game on the Switch has an **NPDM** (Nintendo Process Definition Metadata)
baked into its executable. The NPDM contains a bitmask of which fsp-srv
commands this game is allowed to use.

Before Try25's PID promotion, Civilization VII's observed permission map looked
like this:

| Command | Result | Meaning |
|---|---|---|
| FreeSpace (11) | ✅ Allowed | Query free space on save |
| GetEntryType (7) | ✅ Allowed | Check if a path is a file or directory |
| CreateFile (0) | ✅ Allowed | Create files on the save partition |
| Commit (10) | ✅ Allowed | Flush writes to storage |
| OpenDataStorageByCurrentProcess (200) | ✅ Allowed | Read our own game content (NCA) |
| **OpenSdCardFileSystem (18)** | ❌ **desc=6400** | **Permission denied** |
| **OpenContentStorageFS (110, domain)** | ❌ **desc=6400** | **Permission denied** |
| **OpenSaveDataInfoReader (60)** | ❌ **desc=6400** | **Permission denied** |

The allowed commands used by Try 009 are enough to write and clean up a
throwaway save tree, query paths, and read the game's own content storage.
Several tested commands that would open privileged filesystems were refused.

> **Verified response:** `desc=6400` is the observed refusal for the denied
> commands above. It is consistent with a permission-mask denial; the precise
> interpretation comes from the permission analysis in F12–F13.

**After promotion (Try25):** `OpenContentStorageFileSystem(User=1)` (cmd 110)
returned an `IFileSystem`, and its root listing returned `/registered` and
`/placehld`. In a separate run, `OpenBisFileSystem(System=31)` (cmd 11) also
returned an `IFileSystem`; `OpenDirectory` and `IDirectory::Read` listed
`Contents`, `PRF2SAFE.RCV`, `save`, and `saveMeta` (F69). The BIS open was not
attempted before promotion, so its before/after permission result is unknown.
The payload keeps the User content-storage check and no longer opens BIS.

These were read-only command sequences. The returned filesystem interfaces
are not assumed to be intrinsically read-only; the code scoped their use to
opening `/`, reading entries, and closing handles. No BIS mutation command
was sent.

---

## 5. Step 3 — The Permission Boundary

Commands like `OpenSdCardFileSystem` and `OpenBisFileSystem` are controlled by
fsp-srv's filesystem access checks. Probes confirmed that `OpenSdCardFileSystem`
and `OpenContentStorageFileSystem` are refused under the game's normal
permissions (F12–F13). Try25 later opened User content storage after promotion;
one run also opened and read the System BIS root (F69).

Can we forge the PID? **No.** The kernel writes the real PID into a special
IPC header field, and fsp-srv trusts that kernel-provided value. The client
value is discarded server-side:

```cpp
// Atmosphère source (SF framework):
void MarshalProcessId(ClientProcessId &client, const ProcessId &kernel_pid) {
    client.SetValue(kernel_pid);  // kernel always wins
}
```

Can we change our NPDM? **No.** It's signed and verified at launch.

Can we talk to the kernel directly? **Very limited.** We can use SVCs
(Supervisor Calls), but there is no SVC to change a process's permissions.

Try25 did not forge the kernel-supplied IPC PID. It used the retained memory
endpoint to change the PID fields in the fsp-srv root, NCA backend, and save
backend objects after registration. fsp-srv then accepted the elevated User
content-storage open; the separate BIS listing also succeeded after promotion.
The exact System BIS command was not tested before promotion, so its baseline
denial is not directly established. The payload omits BIS access and
retains only the User content-storage permission check.

---

## 6. Step 4 — The Reference Idea: Corrupt fsp-srv's Memory

The proposed second stage comes from **ns2jb**, by Kurumuz:

> fsp-srv is just a userland process, like the game. It has a heap, with
> data structures, pointers, and stored values. If a request can **overflow a
> buffer inside fsp-srv**, it may corrupt internal state, potentially including
> the stored PID for our session.

This is a reference model, not a result of Try 009. That try sent the
reference-aligned positive `GetEntryType` path and observed the canary change
temporarily during the race. It did not inspect fsp-srv memory or identify the
object responsible for the change.

The specific path-normalization overflow described below is **not** the
mechanism Try25 used. This project established fsp-srv memory access through
the reserved-gap race and cache alias, then installed the retained endpoint to
change the verified identity objects. The reference overflow remains
unverified locally.

**Reference model — not yet established locally:**
```
Our process                         fsp-srv process
┌──────────┐                        ┌──────────────────────────┐
│           │   IPC: GetEntryType    │                          │
│  craft    │   with long path       │  path normalization:     │
│  evil     │ ────────────────────── │  alloc 0x301 bytes       │
│  path     │                        │  alleged overflow        │
│           │                        │           ↓              │
│           │                        │  [adjacent object]       │
│           │                        │  BufferedStorage cache   │
│           │                        │  pointer may be targeted │
└──────────┘                        └──────────────────────────┘
```

---

## 7. Step 5 — Reference Model: Path Normalization and Heap Corruption

The reference exploit reports a path-normalization overflow in fsp-srv. The
exact allocation and overwrite have not been verified by our probes or Try 009.

### What the reference reports

In the ns2jb analysis, an `IFileSystem::GetEntryType` path containing `/..\`
is handled specially by the normalizer:

1. The normalizer allocates a **0x301-byte buffer** on the heap.
2. It copies the normalized path into that buffer.
3. A sufficiently long normalized path is reported to overflow it.

The reference exploit attempts to arrange a useful adjacent object, described
as a `BufferedStorage` cache entry. These details are **reference claims**;
Try 009 did not establish the buffer size, an overflow, or which object was
adjacent.

### What is BufferedStorage?

The reference analysis describes `BufferedStorage` as a caching layer. Its
cache entry is said to contain a backing-buffer pointer, roughly:

```
BufferedStorage cache entry:
┌────────────────────┐
│ valid flag         │
│ dirty flag         │
│ offset             │
│ *** buffer pointer *** ← proposed target
│ buffer size        │
│ ...                │
└────────────────────┘
```

The reference model says that changing this pointer could redirect reads or
writes through that cache entry. If this works as described:

- **Reading** from that cache entry would read from a chosen address in fsp-srv.
- **Writing** to that cache entry would write to a chosen address in fsp-srv.

Together, those operations could provide arbitrary read/write (ARW) in
fsp-srv. **No ARW has been demonstrated in this project.** Try 009 stopped
before testing a cache alias or performing an `IStorage::Write` through one
(F49).

---

## 8. Step 6 — Reserved-Gap Race and ARW Hypothesis

The reference exploit uses a reservation group and a timed wave to try to put
the path-normalization operation next to useful filesystem state. Try 009
reproduced the wave and a canary redirect. It did **not** show that a cache
entry landed in a particular gap or that its pointer changed.

### 8.1 — What the local wave does

Each wave writes 8 MiB of dirty data to a scratch save file, creates a
fresh reservation group with 59 cmd-1200 objects, and starts 13 raw worker
threads. The roles and commands in Try 009 are:

| Role | Worker | Try 009 operation |
|---|---:|---|
| **commit** | W0 | `IFileSystem::Commit` (cmd 10) on the save client |
| **bottleneck** | W1 | `IStorage::Read` (cmd 0), 64 KiB from the game's content storage |
| **frag0–frag3** | W2–W5 | Four `cmd 1002` tail requests |
| **canary** | W6 | `GetEntryType` (cmd 7) for the canary file |
| **filler0–filler1** | W7–W8 | Two `RenameFile` (cmd 5) path-pair requests |
| **release** | W9 | Pin/counter support calls, then close the reservation-group object |
| **guard0–guard1** | W10–W11 | Two `RenameFile` (cmd 5) path-pair requests used by the timing checks |
| **trigger** | W12 | `GetEntryType` (cmd 7) with the profile's long path payload |

The worker threads are created with raw `svcCreateThread` calls. The
reference reports that the SDK thread-creation path hangs in this exploit
setup (F38); our probes confirmed that raw workers can issue overlapping
client-side IPC calls. The workers use shared gates to coordinate. Their
send intervals and completion times do not by themselves prove that fsp-srv
executed all requests simultaneously.

### 8.2 — Timing and qualification

The requests start at staggered times. The trigger waits for the reservation
release and guard signal, then checks the abort gates before sending its
`GetEntryType` request. A wave counts as a receive window only when the
reservation, worker, response, and timing checks all pass.

The reference lifetime check divides ten roles into two groups:

- **Through roles:** `commit` and `frag0–frag3` remain active across the
  trigger call.
- **Held roles:** `canary`, both fillers, and both guards are active when the
  trigger starts. They do not all need to outlast the trigger.

The bottleneck read must also finish at least 300 µs after `guard1` starts.
Try 009 measures the first pin request inside the canary request's lifetime
and checks the Civ VII pin cost (6,960 bytes, with ±192 bytes of heap jitter).
The receive-window result also requires 13/13 workers to be created, started,
completed, and joined; 59/59 reservations; successful main transports;
expected tail/control responses; and restored allocation counters. These are
timing and setup checks, not proof of cache-pointer corruption (F44, F49).

### 8.3 — Reference mechanism versus local evidence

**Reference model:** the 59 reservations and their release shape fsp-srv's
heap; `Commit` and other filesystem operations create the target allocation
state; the long `GetEntryType` path then corrupts a `BufferedStorage` cache
entry. The exact object placement and pointer overwrite remain unverified on
this console.

**Verified in Try 009:** the 59-object group was created and released, the
13-worker timing checks passed, and the positive profile temporarily changed
the canary's reported entry type. The test did not choose an address, verify a
cache alias, or perform arbitrary reads or writes.

**Cache behavior:** Try 009 does not call `IStorage::OperateRange` to
invalidate the content cache, and it removed the earlier synchronous NCA
warm-up reads. Its bottleneck is a 64 KiB read; later waves measured roughly
3.1–3.7 ms. Whether this read reached physical media is unknown. The current
reference-aligned Civ VII read size is 64 KiB, not the 1.5 MiB value used by
older probes or one older reference.

---

## 9. Step 7 — Try 009: Controlled Race and Canary Redirect

Try 009 prepares the canary and path targets, then runs reference-style
controls before its positive profile:

1. Open two clones of the mounted `save` filesystem: `saved` for the canary,
   selected directory, and dirty file; `temporary` for the `SPAN_*` marker
   tree. Extent-profile triggers use the matching temporary client.
2. Open the game's content storage with cmd 200, plus the auxiliary storage
   handle used to match reference object lifetimes.
3. Before each wave, write 8 MiB to the scratch `commit_data` file. Open a
   fresh fsp-srv domain session for that wave's 59 cmd-1200 reservations.
4. Run the 13 staged raw workers, gather their responses and timing spans, and
   close the reservation group. Repeat the current control or positive
   profile as needed, up to the script's 20-wave bound.
5. After the wave, query canary health again. A qualified canary redirect
   requires the in-wave result to be the only changed monitored path and the
   post-wave canary query to return the original file type.
6. Delete the scratch tree and commit cleanup.

The positive profile uses a `0x2440`-byte path payload plus its terminating
NUL. It starts with `/..\`, inserts `/` after each 200 filler characters to
respect the BC-save component limit, and places the existing `selected`
directory path near offset `0x2340`. The test also creates the `SPAN_MARKER`
tree through the `temporary` save client for the preceding extent-present
profile. This describes the payload Try 009 sent; it does not prove that the
normalizer overflowed.

The recorded run had this profile sequence and result (F49):

| Wave | Profile | Timing / control result | Canary result |
|---|---|---|---|
| W01 | `abort-control` | Pin interval did not qualify; trigger aborted | File, type 1 |
| W02 | `abort-control` | Pin qualified: 6,960 bytes, within canary interval; state restored | File, type 1 |
| W03 | `abort-hole-control` | 10/10 timing shape; expected abort control passed | File, type 1 |
| W04 | `extent-absent` | 10/10; absent marker did not select an extent | File, type 1 |
| W05 | `extent-present` | 10/10; marker selected and receive window qualified | File, type 1 |
| W06 | `negative` | 10/10; negative path control passed | File, type 1 |
| W07 | `positive` | 10/10; margin +1,436 µs; only canary changed in-wave | **Directory, type 0 in-wave; file, type 1 after wave** |

All seven waves created and joined 13/13 workers; each created all 59
reservations, and scratch cleanup succeeded. The control sequence makes the
canary change meaningful: the absent-marker control did not qualify, the
negative control left it alone, and the positive profile produced the only
redirect. The user reports successful redirects on multiple launches; the
run table above is one recorded sequence.

**What this establishes:** Try 009 reproduced the reference's canary
redirection behavior during the positive race on this Switch 2 / firmware
23.0.1 / Civ VII 1.0.0 setup. Because the canary returned as a file in the
post-wave health check, the observation is consistent with a temporary
path-resolution change during the overlap.

**What it does not establish:** no candidate offset, cache alias, direct
fsp-srv memory read/write, or PID overwrite was attempted. The canary result
does not by itself identify the internal mechanism. The `0x301` normalizer
buffer and `BufferedStorage` pointer target remain reference-model claims.

### BC-Save Constraints (Civ VII Specific)

| Constraint | Evidence | How Try 009 handles it |
|---|---|---|
| **Outstanding dirty data** | Reference testing reports 8 MiB succeeds and 12 MiB fails; 16 MiB can poison the save session (F37) | Caps each wave's dirty file write at 8 MiB |
| **Path component length** | The BC save rejects components over 255 characters with FS error 2-6006 (reference result, F39) | Splits the positive filler path every 200 characters |
| **Save health** | Reference runs report lower win rates after incomplete runs (F40) | Uses bounded waves and cleans up; user reports multiple successful launches |

---

## 10. Step 8 — Try 010: Candidate IStorage Baseline

After the canary redirect, Try 010 opens a **candidate IStorage** through
`OpenDataStorageByCurrentProcess` (cmd 200). This creates a new C++ object in
fsp-srv's heap that accesses the game's NCA content. The candidate is the
object whose cache entry we will later corrupt.

### 10.1 — Why a separate handle?

We already have a primary `storageHandle` (opened during setup). The candidate
is a *second* handle to the same NCA. Both return identical data, but they have
separate cache entries in fsp-srv's heap:

```
fsp-srv heap:
┌───────────────┐
│ primary        │ ← storageHandle (opened at setup, used for control reads)
│ IStorage #1    │
│ cache entry    │
├───────────────┤
│ candidate      │ ← candidateHandle (opened post-canary, target for alias)
│ IStorage #2    │
│ cache entry    │  ← we will corrupt THIS one
├───────────────┤
│ other objects  │
└───────────────┘
```

### 10.2 — Baseline measurements (F50)

| Measurement | Value |
|---|---|
| NCA size (GetSize) | 4,975,206,648 bytes (4.7 GiB) |
| Allocation cost (cmd-200) | exactly 6,960 bytes |
| Content at offset 0 | `5000000000000000d046552801000000` (NCA header) |
| Content at aliasOffset (0x1400000) | `61df639c95ac6da473d636d2c17b888d` (game data) |
| Candidate matches primary | Yes — same NCA backend |

The two offsets return *different* data. This is essential: after installing
the alias, a read at aliasOffset that returns offset-0 data proves the cache
was modified.

The 6,960-byte allocation matches both Kurumuz and Slapah references for
Civ VII. This means the heap geometry is as the references expect — the
candidate's cache entry is at a predictable location relative to the 59-object
reservation group.

---

## 11. Step 9 — Try 011: Cache Alias Confirmed

This is the first step that **writes controlled data into fsp-srv's heap**.
Try 011 uses 7 TOCTOU race waves to modify the candidate's cache entry,
making it redirect reads from one NCA offset to another.

### 11.1 — What is a cache alias?

Each IStorage's cache entry records *which NCA offset* the cached data came
from:

```
Before alias:                      After alias:
┌────────────────────┐             ┌────────────────────┐
│ offset: 0x0        │             │ offset: 0x1400000  │ ← modified!
│ marker: <original> │             │ marker: 0x41414141 │ ← modified!
│ dirty:  0          │             │ dirty:  1          │ ← modified!
│ data:   NCA[0:16K] │             │ data:   NCA[0:16K] │ ← unchanged!
└────────────────────┘             └────────────────────┘
```

The **data** stays the same (NCA content from offset 0), but the **metadata**
now says "I have data for offset 0x1400000." When we read at 0x1400000,
fsp-srv finds this cache entry, thinks it matches, and serves the old data
from offset 0.

**Analogy:** a library shelf label says "History Section." Someone changes the
label to "Science Section." Now anyone looking for science books goes to that
shelf and finds history books instead. The books didn't move — only the label
changed.

### 11.2 — The nulWrites mechanism

We want to write 18 specific bytes at offset `markerOffset` (0x2340) in the
TOCTOU payload, which correspond to the cache entry's metadata fields. But
the TOCTOU race copies data via a **NUL-terminated string copy** (like C's
`strcpy`) — it stops at the first 0x00 byte.

Problem: our 18-byte prefix contains *six* NUL bytes:

```
00 00 40 01 00 00 00 00 41 41 41 41 41 41 41 41 01 00
^^    ^^    ^^ ^^ ^^ ^^                            ^^
NUL   NUL   NUL NUL NUL NUL                        NUL (trailing)
```

Solution: write the prefix in **7 progressively shorter steps**, each leaving
a NUL at one position while preserving bytes from earlier steps:

```
Step 1 (17 bytes): BB@\x01BBBB AAAAAAAA \x01 \0  ← full prefix, NULs → 'B'
Step 2 ( 7 bytes): BB@\x01BBB \0 ...preserved...  ← NUL at position 7
Step 3 ( 6 bytes): BB@\x01BB \0 ...preserved...   ← NUL at position 6
Step 4 ( 5 bytes): BB@\x01B \0 ...preserved...    ← NUL at position 5
Step 5 ( 4 bytes): BB@\x01 \0 ...preserved...     ← NUL at position 4
Step 6 ( 1 byte ): B \0 ...preserved...            ← NUL at position 1
Step 7 ( 0 bytes): \0 ...preserved...              ← NUL at position 0
```

Each step uses a TOCTOU wave with a **copyField** payload: the trigger sends a
`GetEntryType` with a path starting with `/../\`, filled with `B`, and the
step's tail bytes at markerOffset. The path exceeds the 255-character component
limit, so fsp-srv rejects it — but the bytes have already been copied into the
internal buffer that overlaps with the cache entry.

### 11.3 — Acceptance criteria for cache writes

A cache-write wave is "accepted" when:

1. **Window qualified** — 10/10 timing shape, margin ≥ 300 µs, no abort
2. **preReleaseUsed ≥ 0x2810** — enough fsp-srv heap was held (tighter than
   the 0x2600 threshold for positive waves)
3. **changedPaths == 0** — the canary stayed as a file (type 1)

Criterion 3 is the key distinction from positive waves. In a positive wave,
the canary changes (type 1 → 0) — the race redirected the canary path. In a
cache-write wave, the canary does *not* change — the race wrote to the cache
entry instead. Same race mechanism, different payload, different outcome.

### 11.4 — Results (F51)

| Step | Attempts | Best margin | Result |
|------|----------|-------------|--------|
| 0 (end=17) | 5 | 1192 µs | OK |
| 1 (end=7) | 6 | 1076 µs | OK |
| 2 (end=6) | 1 | 890 µs | OK |
| 3 (end=5) | 1 | 923 µs | OK |
| 4 (end=4) | 1 | 1067 µs | OK |
| 5 (end=1) | 1 | 1071 µs | OK |
| 6 (end=0) | 3 | 1017 µs | OK |

18 cache-write waves total. Steps 2-5 accepted on the first attempt.

**Verification:** reading candidate at 0x1400000 returned
`5000000000000000d046552801000000` — the NCA header from offset 0.
`selectedAlias=true`.

### 11.5 — Cache invalidation failure

After verifying the alias, Try 011 attempted to restore the cache with
`IStorage::OperateRange` (cmd 5, operation 2 = invalidate). The operation
returned error `0x5` — not supported or rejected on firmware 23.0.1 for a
corrupted cache entry (F46, F51).

After the failed invalidation, reads from candidateHandle return success
(result 0) but produce no data (the output buffer keeps its poison pattern).
The IStorage object is in a broken internal state. This does not affect future
steps: the candidate is treated as consumed, and new candidates can be opened.

---

## 12. Step 10 — Try 012–014: Widened Read and Heap Pointer Leak

With the cache alias confirmed, the next step reads **2 MiB** (0x200000 bytes)
from the aliased candidate instead of just 16 bytes. The cache entry's data
area holds approximately 16 KiB of NCA content, but fsp-srv's read path
copies as much as the request asks for. The bytes beyond the cache data come
from **adjacent heap memory** in fsp-srv.

```
What a 2 MiB aliased read returns:
┌─────────────────────────────┐ offset 0
│ Cache data (~16 KiB)         │ ← legitimate NCA content from offset 0
├─────────────────────────────┤ ~16 KiB
│ Adjacent heap objects         │ ← free-list pointers, cache metadata,
│ (up to ~2 MiB)               │   allocation pool entries
└─────────────────────────────┘ 2 MiB
```

### 12.1 — Try 012: Widened read confirms heap visibility

Try 012 extended the alias read from 16 bytes to 2 MiB (F51). The first
16 KiB matched the control NCA data; beyond that, the data transitioned to
heap content — structured metadata blocks and encrypted NCA cache pages from
other IStorage handles. The 2 MiB window was fully populated.

### 12.2 — The fragmentation problem

A bare widened read shows heap data but no **pointers**. All 127 blocks (at
0x4000 boundaries) contain occupied data. To see free-list pointers, we need
to **free** cache blocks within our window and observe the allocator writing
"next" pointers into the first 8 bytes of each freed block.

The reference (Kurumuz) uses `IStorage::OperateRange` (operation 2 =
invalidate) to free cache buffers without closing handles. On firmware 23.0.1,
this operation returns error `0x5` — not supported (F51). An alternative was
needed.

### 12.3 — Try 013–014: Sequential handle closure with priming

**Key insight from the reference:** the fragmentation cycle reads through
neighbor handles at **multiple offsets** (0, 0x4000, 0x8000, ...) to force
many cache page allocations in fsp-srv's cache pool. Try 013 closed 3 handles
at once (too few, wrong heap direction); Try 014 v1 closed them sequentially
(caches outside the window); Try 014 v2 added extra handles but with only 1
page per handle (insufficient coverage).

**The fix (Try 014 v3):** after installing the cache alias, open 6–8 extra
IStorage handles and read 16 bytes at **16 different offsets** per handle.
This forces 96+ cache page allocations in fsp-srv's cache pool, filling the
2 MiB alias window with freeable blocks.

Then close handles **one at a time**, taking a snapshot after each closure.
Each closure frees that handle's cache pages. The allocator writes a free-list
"next" pointer into the first 8 bytes of each freed page while leaving the
rest (NCA data) untouched. This is the **changedLink** pattern: head changed,
tail identical.

### 12.4 — Results: 7 heap pointers (F52)

| Round | Handle closed | Changed blocks | Qualified pointers |
|-------|--------------|---------------|-------------------|
| 1 | extra0 | 1 | 0 (NULL = end of free list) |
| 2 | extra1 | 7 | **6** (heap pointers) |
| 3 | extra2 | 1 | **1** (pointer chain update) |
| 4–9 | extra3–5, pin, aux, storage | 0 | 0 (caches outside window) |

All 7 pointers are in the range `0x2df2980000`–`0x2df2eb0000` (~5.2 MiB
span), 0x4000-aligned, within the 39-bit virtual address space. They form a
consistent free-list chain:

```
Round 1:  @0xc000 head: NCA data → 0x0        (first freed block, end of list)
Round 2:  @0xc000 head: 0x0 → 0x2df2980000    (updated: points to newly freed block)
Round 2:  @0x4c000, @0x58000, @0x60000, @0x64000, @0x78000 → heap pointers
Round 3:  @0x78000 head: 0x2df2cdc000 → 0x2df2cb4000  (chain grows)
```

**What this establishes:** the fsp-srv heap base is around `0x2df2xxxxxx`.
ASLR is broken — we know where fsp-srv's cache pool lives in virtual memory.
This is the information needed for the address planning step.

This entire phase is **read-only** plus handle lifecycle operations (open,
read, close). No writes to fsp-srv memory beyond the already-installed cache
alias.

---

## 13. Step 11 — Try18–25: Metadata, Root Identity, and Permission Promotion

The heap leak gave us candidate addresses, but a plausible pointer is not
enough to identify an SDK object. The reference workflow derives a metadata
page from an allocator link, captures the nearby layout, and uses the live
session's domain ID to locate its root object. Try20's first table search did
not match; Try23 later verified the caller-owned root, and Try24/Try25
rediscovered the current root and backend objects before using them (F58,
F61–F62).

### 13.1 — Qualify an address-read path (Try18)

Try18 passed its canary, alias, and `0x28000` period checks. It then read
`0x4000` bytes twice through its signed address plan and got stable,
non-poison data. This qualifies the script's bounded read path. It does not
independently prove that every returned byte came from the planned fsp-srv
address or that the target is an SDK metadata page (F53).

### 13.2 — Derive and validate a metadata page (Try20)

Try19 had used the changed-link target directly as the layout-capture start.
Both bounded captures were readable but found no domain wrappers or manager
groups. The reference workflow instead searches a seed window for aligned
native links, narrows pool candidates, and validates an allocator
`externalLink`. A plausible link has reciprocal `next`/`previous` pointers
and a plausible extent; its `next` pointer supplies the metadata-page
candidate. The page guard then checks repeated-read stability, the expected
reciprocal node pair, and that the bytes differ from ordinary storage (F56).

Try20 passed that page guard. Its accepted example was node
`0x5d77600000`, `next=previous=0x6529dee978`, extent `0xe00000`, page
`0x6529dee000`, with anchor offset `0x978`. From that page, it captured
`0x4d8000` bytes in 31 chunks over
`[0x65298ee000, 0x6529dc6000)`. The capture contained 39 recognized domain
wrappers and one vtable/manager group (F58).

### 13.3 — Relate the domain ID to the root object

`openDomainSession()` converts a newly opened fsp-srv session to domain mode
and returns the root domain-object ID from `ConvertToDomain`. That ID is a
domain-table index, not a PID. The reference computes the entry address as
`table + (id - 1) * 0x30`, then checks the object's vtable and relationship
to the manager (F13, F56).

In Try20, the separate domain session returned root ID `134`, but none of the
captured table entries matched (F58). Try23 resolved this by pairing the
current session handle and root ID, matching the caller-owned entry and wrapper,
then validating the root object with a reversible clone-count challenge before
reading its PID (F61). Try24 rediscovered the root, NCA backend, and save
backend from fresh captures and verified their layouts and snapshots (F62).
Addresses and PIDs remain run-specific; later tries must rediscover them.

### 13.4 — Promote the FS-side identity and check access (Try25)

The reference helper `fs-root-pid.cjs` describes a root-object PID at `+0x30`,
NCA backend PID at `+0x20`, and save backend PID at `+0x28`. Try23 verified the
root object and PID after the reversible clone-count challenge (F61). Try24
rediscovered all three identity objects and their fields from fresh captures
(F62).

Try25 used the retained two-bucket memory endpoint to set the root, NCA, and
save PID fields to `1`, then checked complete-object readback. This changes
fsp-srv's stored identity for those objects; it does not change the game's
kernel PID or forge the IPC special header. The reference maps stored PIDs
`1`–`6` to a broad FS permission mask; Try25's successful privileged opens
provide runtime evidence that this path works for the tested commands.

After promotion, `OpenContentStorageFileSystem(User=1)` succeeded and its root
listing returned `registered` and `placehld`. In a separate run, Try25 also
opened `OpenBisFileSystem(System=31)` and read `Contents`, `PRF2SAFE.RCV`,
`save`, and `saveMeta`; the IDirectory and IFileSystem handles both closed
successfully (F69). The exact BIS-open command was not tried before promotion,
so a before/after denial comparison for that command remains unknown.

The first recorded promotion run restored the complete root, NCA, and save
objects exactly, then S21 rejected cleanup because a control descriptor had
already been consumed (F68). The later BIS log excerpt ends before restoration
and cleanup, so it does not establish those final steps for that run. The
payload has since removed the BIS open/listing path; it keeps the User
content-storage check as its permission proof.

> **Save-side effect:** the metadata and object inspection is intended to be
> read-only, but the Try20 setup still used temporary writes to
> `save:/hole`; cleanup deleted that tree and issued `Commit`. The recorded
> run reports that cleanup and handle closure succeeded. This is separate
> from the target-memory reads, which did not write the root or backend PID.

> **Safety boundary:** no BIS or system-NAND mutation has been performed. A
> read-only System BIS listing was run once to confirm access, then removed from
> the payload flow. The `IFileSystem` handle is not treated as intrinsically
> read-only; the tested code issued only directory open/read/close commands.
> PID promotion is temporary and the full original objects were verified during
> a recorded run. Cleanup status must be checked from that run's complete log.

---

## 14. Current Status of the Chain

```
 STAGE                         STATUS            EVIDENCE / RESULT
 ──────────────────────────────────────────────────────────────────────
 0. Userland code execution     Assumed input      CivSwitch provides game-process R/W
 1. Open fsp-srv session        Verified           SM session + process registration
 2. Use domain IPC              Verified           Domain commands and object routing
 3. Map permissions             Verified           Allowed save/content commands; denials
 4. Prepare wave                Verified           Two save clients, content storage, scratch tree
 5. Create and release group    Verified           59 cmd-1200 reservations per wave
 6. Run controlled race         Verified           13/13 worker lifecycle; timing controls
 7. Redirect canary             Verified           Temporary type 1 → 0 in positive W07 (F49)
 8. Candidate IStorage baseline Verified           6,960-byte alloc, NCA content matches (F50)
 9. Cache alias installed       Verified           7-step nulWrites; read at 0x1400000
                                                   returns offset-0 data (F51)
10. Heap pointer leak           Verified           7 changedLink pointers in 0x2df2xxxxxx;
                                                   free-list chain observed (F52)
11. Address-read qualification  Verified           Try18 guards; later root/backend proofs (F53, F61–F62)
12. Metadata page derivation    Verified           Try20: external link + page guard (F58)
13. Bounded layout capture      Verified           0x4d8000; 39 wrappers, one group (F58)
14. Root table match            Verified           Try23 matched current root and wrapper (F61)
15. Root/backend PID read       Verified           Try23/Try24 checked fresh objects (F61–F62)
16. Elevated FS permissions     Verified           Try25 User storage; one BIS listing (F69)
```

**In plain words:** the project has confirmed the cache alias and observed
free-list pointers in fsp-srv's cache pool. Try18 qualified a bounded read
path; Try20 validated a metadata page; Try23 matched the current root object
and proved its PID; Try24 rediscovered the root and both backends; and Try25
temporarily promoted their FS-side PID fields. The User content-storage
permission check remains in the payload. System BIS listing succeeded once
and is documented as a historical result, but its code was removed from the
payload. The exact System BIS permission result before promotion and the
final cleanup tail for the later listing run remain unconfirmed.

---

## 15. Glossary

| Term | Meaning |
|---|---|
| **ARW** | Arbitrary Read/Write — the ability to read or write any memory address in a process |
| **BC save** | Backward-Compatible save — the save format Civ VII uses, with specific size limits |
| **BufferedStorage** | Cache layer described by the references as sitting between the FS API and backing storage |
| **Cache alias** | Corrupting a cache entry's offset field so reads at one offset return data cached from another |
| **copyField** | Technique to write arbitrary bytes via the TOCTOU race: the canary stays unchanged while bytes land in the cache |
| **CMIF** | Common Message Interface Framework — the serialization format inside IPC messages |
| **Domain mode** | IPC mode that multiplexes multiple object interfaces over one session handle |
| **fsp-srv** | Filesystem Proxy Service — the Horizon OS process that handles all FS operations |
| **Heap shaping** | Deliberately allocating/freeing objects to control where new allocations land |
| **HIPC** | Horizon IPC — the kernel-level message transport between processes |
| **IPC** | Inter-Process Communication — how processes on Horizon OS talk to each other |
| **NCA** | Nintendo Content Archive — the encrypted container for game data |
| **nulWrites** | Algorithm to install bytes containing NULs via NUL-terminated string copies, using progressively shorter writes |
| **NPDM** | Nintendo Process Definition Metadata — defines a process's permissions, signed |
| **PID** | Process ID — unique number identifying each process; the PID ≤ 6 permission mapping is a reference claim |
| **Reservation group** | A set of domain objects opened via cmd 1200; the references use it to shape heap allocations |
| **Sequential release** | Closing IStorage handles one at a time with snapshots between each, to observe free-list pointer changes |
| **ROP** | Return-Oriented Programming — technique to call existing code sequences |
| **SM** | Service Manager — the system service that maps service names to IPC handles |
| **SVC** | Supervisor Call — the ARM64 mechanism for userland to call into the kernel |
| **Wave** | One staged attempt with the 13-worker race; a qualified timing window is not by itself an exploit win |
| **Widened read** | Reading 2 MiB through an aliased cache entry to leak adjacent fsp-srv heap memory |

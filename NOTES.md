# relapse-y2jb — notes

Detail behind [README.md](README.md): what the payload does, how to read its
output, the constraints it works under, and the hardware investigation into why
the host app cannot be closed.

## What it does

1. Runs Relapse's kernel stage verbatim — KASLR leak, the `aio_multi_wait`
   use-after-free race, a sysctl-OID write window, then crossed pipes for fast
   kernel read/write.
2. Escalates the YouTube process: uid 0, full `sceCaps`, sandbox off, root
   filesystem, unrestricted syscall range.
3. Prepares the state Y2JB's kernel payload expects — widened `eboot` segment
   descriptors and `fhold` on the pipe files — then hands the crossed pipes and
   `allproc` to the `kexp` blob Y2JB already downloaded, which starts `elfldr`.
4. Puts back everything it can on the way out: the sysctl OIDs, the pipe
   crossing, the armed aio groups, the parked aio workers, the scratch
   descriptors, and `eboot`'s original segment descriptors. Teardown runs in
   upstream Relapse's order, which matters — see below.

Anything sent to port 9021 after that is loaded as an ELF.

## Requirements, in detail

**Firmware.** 33 offset tables are built in, covering 7.00 through 13.60. On
anything else the payload refuses to run rather than guessing at offsets.

**The `kexp` blob and `elfldr`.** These are not embedded; they are read from the
Y2JB sandbox slot, which is where Y2JB itself keeps them:

```
/mnt/sandbox/<titleid>_000/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/
```

Slots `_000`, `_001` and `_002` are tried, then `/mnt/usb0` … `/mnt/usb7`, then
the directories are listed and matched by pattern. Accepted names:
`kexp_2026_05_25.bin` or `kexp.bin`, and `elfldr-ps5-1360.elf`,
`elfldr-ps5-0.23.elf`, `elfldr_1320_v5.elf` or `elfldr.elf`. If your Y2JB
release ships differently named files, that is the first thing to check.

**Loader size.** The Y2JB remote JS loader reads at most `0x40000` (256 KiB).
A larger payload arrives truncated and the console reports
`SyntaxError: Unexpected end of input`, which looks like a bug in your edit and
is not. `relapse.js` is ~241 KB, leaving ~21 KB of headroom.

## Logging

Every line goes to the sender over the TCP connection, and is also mirrored with
a bare `sendto()` to UDP port 5050 on whichever address sent the payload. The
UDP copy is the one that survives a kernel panic, so it is worth capturing:

```bash
nc -u -l 5050
```

A normal run is about thirty lines: the KASLR base, slow and then fast kernel
read/write, the aio group check, privileges, two preparation lines, the blob and
`elfldr` delivery steps `1/6` through `7`, the shellcode's return value, `:9021`
coming up, and the teardown.

## One run per boot

A successful run leaves a marker at `/user/temp/common_temp/relapse.fail`, and a
second attempt in the same boot refuses and tells you to reboot. Racing the aio
UAF on top of an already-exploited kernel is how a working jailbreak turns into
a panic, so the marker is deliberate. It is cleared automatically when a run
stops cleanly without jailbreaking — including when the payload refuses because
the process is already jailbroken.

If you are experimenting and know the kernel is clean, the check can be
overridden at build time (`--set IGNORE_FAIL_MARKER=true`).

## Known limitation: closing the host app panics the console

Exiting the YouTube process after a jailbreak black-screens the console
immediately, with no dump. The payload's own teardown does not prevent it.

The browser flow only *looks* immune. Pressing the PS button closes the browser
**window** while the process stays resident, so the kernel's exit path never
runs. Closing an app really does exit the process, and that is where it dies.

### What hardware testing established

The trigger is **the pipe crossing** — `crossPipes()`, which is what creates the
fast kernel read/write primitive. One run did the entire aio race (the sysctl OID
hijack, the reclaim, the parked workers) and stopped before crossing: it survived
the close. The same payload with the crossing added panics. Neither run had the
kexp prep, the blob, the handoff or the escalation.

What that leaves is a mechanism nobody has observed yet. Everything the exploit
writes into the two `struct pipe`s is irrelevant to it: a cleanup ELF with kernel
read/write of its own nulled both buffers, all eight head fields and the
direct-write pair, verified every readback, and the close still panicked. So the
residue is outside the structs — the global `pipe_map` VM map, the two original
buffers the crossing leaks, the KVA accounting — or the fault is not in the pipe
teardown at all.

Exonerated on hardware, one reboot per row:

* **The aio race on its own**, including every fake waiter node. All three
  reclaimed arrays were located, zeroed and read back as zero, and all 54 armed
  groups confirmed clear by two independent paths.
* **The sysctl OIDs**, restored in upstream's order or deliberately left hijacked.
* **Graceful close versus `SIGKILL`.** Identical; the process exit is what kills it.
* **The blob, `elfldr`, `pldmgr`**, the widened `eboot` segments, `fhold` on the
  pipe files, cred migration, and this port's `thr_new`/ROP worker chain.
* **`pipe_buffer.buffer` and `vm_map_remove()`.** An earlier revision stated that
  nulling the buffer makes the exit path's removal a no-op. It does null it, and
  it does not help.

Two cleanups are themselves fatal and must not be enabled:

* Nulling `p_aioinfo` to "leak" the aio state — spontaneous panic, seconds after
  the write, with the app still open.
* Restoring the OIDs through the slow window *after* the pipes are disarmed.
  `restoreOidsSlow()` restores the window through the window, and `aimWindow()`
  steers by moving `arg1` pointers, so restoring `a.arg1` destroys the mechanism
  the next write needs.

### Corrections to an earlier revision of this note

Worth recording, because both were believed and acted on.

* **"`p_aioinfo` is already NULL by the time the run finishes, so there is nothing
  to detach."** False. The diagnostics used `readKernelPointer()`, which is the
  slow sysctl-OID path, and every forensic call ran after `restoreOids()` had
  closed it. A dead slow path returns null instead of throwing, and the callers
  read that as an answer. `p_aioinfo` is live at teardown.
* **"The residue is the poisoned slab the race leaves behind."** False, and it
  followed from the first error plus misreading `dumpAioState()`, which took
  `num`/`state`/`waiters` off the group object instead of the shared struct one
  indirection further (`group+0x10`) and so reported request ids as states. The
  poison was then located and scrubbed directly, and scrubbing it changed nothing.

### Workaround

There is no workaround, and none is needed: leave the app open, and if you do
close it, reboot and send the payload again. The run takes about three seconds, so
rebooting costs less than anything that would have to be built to survive the exit
path.

Suspending the console is not a workaround either, and it was withdrawn from this
note before it was ever tested. Nothing executes while the system is suspended, so
`elfldr` would not answer on 9021 and a saved state would have nothing to resume
into. Reboot.

The full log — every build, every result, the flags, and the next experiments — is
`docs/close-panic-investigation.md` in
[Relapse-Y2JB-Porting](https://github.com/edisnord/Relapse-Y2JB-Porting).

## Debug build

The release payload has all forensics switched off. A debug build adds:

* a snapshot of the process's kernel-visible state immediately before and after
  the handoff — `p_ucred` and its fields, every `f_cred`, every `td_ucred`, the
  filedesc table, the dynlib syscall range, both pipe buffers — so the diff
  shows exactly what the `kexp` blob changed. Every pointer is range-checked
  before it is dereferenced. (This is how the blob's fd-table swap was found:
  256 entries at a heap address became 768 entries in a different region.)
* a read-only dump of the reclaimed aio waiter arrays, taken while the group
  still points at them, logged next to `kbase` and the `nodeMutex` address the
  offset table implies.
* `dlsym` probing, and the p2jb-style `f_cred`/`td_ucred` migration — the only
  two that write.

There are also bisect switches that stop the run at a stage boundary
(`chain`, `arm`, `fast`, `defuse`, `escalate`), skip the handoff entirely, and
close the pipe fds from the payload instead of leaving them to process exit.
`rescue()` still runs on the way out of every one, so each rung is
self-cleaning.

## Source

`relapse.js` is generated. The readable source, the offset tables, the build
system and a fake-host smoke test that runs the payload end to end live in the
`Relapse-Y2JB-Porting` repository, which builds against a checkout of
[upstream Relapse](https://github.com/ntfargo/Relapse-Exploit):

```bash
node tools/build.mjs                                  # -> relapse.js
node tools/build.mjs --set DIAGNOSE_AFTER_HANDOFF=true --out relapse-debug.js
node tools/hostcheck.mjs 12.60                        # runs it against a fake host
```

Comments live in `src/relapse.template.js` and are stripped from the build,
which is what keeps the payload under the loader's size limit.

## Credits

Nothing here is original work; this is a port. Each project below keeps its own
author list in its README, which is the authoritative one.

**[Relapse](https://github.com/ntfargo/Relapse-Exploit)** — the browser stage,
the `aio_multi_wait` UAF kernel stage and all 33 offset tables, used verbatim.

**[Y2JB](https://github.com/Gezine/Y2JB)** — the host this runs inside: the
remote JS loader and its payload protocol, the sandbox slot layout, and the
`kexp` and `elfldr` files it ships. Its README also credits the projects it
draws on, among them
[Remote Lua Loader](https://github.com/shahrilnet/remote_lua_loader) and
[ClosePlayer](https://github.com/BenNoxXD/PS5-BDJ-HEN-loader).

**[kexp](https://github.com/ufm42/kexp)** — the post-jailbreak all-in-one
shellcode this port hands the kernel to. `elfldr` arrives bundled with Y2JB and
is credited in its README.

**[Luac0re / p2jb](https://github.com/Gezine/Luac0re)** and
**[P2JB-Y2JB-Porting](https://github.com/matem6/P2JB-Y2JB-Porting)** — the
`fhold`/`eboot` preparation, the one-run-per-boot marker discipline and the
post-jailbreak cred migration in the debug build all come from that port's
close-panic work, as does the observation that a jailbroken host process cannot
be closed. Its README credits the contributors behind that investigation,
including the people who ran its hardware test builds.

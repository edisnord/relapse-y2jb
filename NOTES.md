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
   descriptors — then hands the crossed pipes and `allproc` to the `kexp` blob
   Y2JB already downloaded, which starts `elfldr`.
4. Puts back what it can on the way out: the sysctl OIDs, the armed aio groups,
   the parked aio workers, the scratch descriptors, and `eboot`'s original
   segment descriptors. Teardown runs in upstream Relapse's order, which matters
   — see below.
5. Leaves the pipes crossed on purpose, because that is what `elfldr`'s kernel
   read/write rides, and writes a note file recording the pipe addresses and the
   buffers they had before the crossing. `seal/pipeclean.elf` reads that note and
   puts the buffers back; see below for why closing without it panics.

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
is not. `relapse.js` is ~254 KB, leaving under 2 KB of headroom — the reason several
diagnostic methods are emitted only under `--diag`.

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

## Closing the app

Closing YouTube after a jailbreak panics the console unless `seal/pipeclean.elf`
has been sent to port 9021 first. This is what the seal does, and why the payload
cannot do it itself.

### What the exploit leaves behind

Fast kernel read/write is built from two pipes. One pipe's `buffer` field is
pointed at the other pipe's `struct pipe`, so a `write()` on the first lands in
the second's fields; the second's `buffer` is then aimed at an arbitrary kernel
address, so a `write()` on it lands anywhere. None of that is undone when the
payload finishes, because `elfldr`'s kernel read/write is the same mechanism and
has to keep working.

If the process exits in that state the kernel tears the pipes down. `pipe_dtor()`
calls `pipe_free_kmem()`, which frees `pipe_buffer.buffer` for `pipe_buffer.size`
bytes — so it hands `kmem_free()` another pipe's struct as though it were a 16 KB
buffer allocation. That is the panic.

### Why the seal restores the buffers rather than clearing them

Setting `buffer` to NULL looks like the fix and is not. A pipe that has been used
and then had its buffer field cleared sits at `buffer = 0, size = 0`, which is not
a state any live pipe is in and which the teardown has no path for. It also
orphans the real allocation while `amountpipekva` goes on counting it. With
everything else held equal, clearing the buffers kills the console within three
seconds of exit and restoring them does not.

So the seal writes each pipe's own buffer and size back — recorded by the payload
before the crossing overwrote them, and left in a note file the seal reads —
zeroes `count`, `in` and `out`, and verifies every field by readback. What is left
is an ordinary used-but-empty pipe, which the kernel frees normally.

The allocation is a `pipepair`, not a single `struct pipe`: the second half sits at
`+0x108` and `+0xe0` holds the peer pointer. Both halves matter.

### Why the payload cannot seal itself

The restore goes through the sysctl-OID write window, the exploit's other
primitive, and has to run while that window is still open. Restoring the OIDs
closes it, and the window cannot restore its own writable `kind`, because that
field is what makes it writable.

Restoring the buffers through the pipes instead runs into a parity limit. Writing
the first pipe's struct requires the second to be aimed at it, writing the second's
requires the first to be aimed at it, and each aim overwrites the field being
repaired — so one of the two is always left pointing at a struct. An ELF with its
own kernel read/write has neither constraint, which is why the seal is a payload.

### A mitigation that was removed

Earlier revisions held the four pipe files at `f_count = 0x10000` so `pipe_dtor()`
could not run at all. That is gone: `holdPipeFiles()` is not emitted into the
production payload and the build rejects the flags that call it without `--diag`.
Once the buffers are real, `pipe_dtor()` is harmless, and all the hold does is leak
four `struct file` objects past process exit, which the teardown still has to
account for. A full production run with the hold died four seconds after exit; the
same run without it survived.

### The seal does not interrupt anything

`:9021` and any payload manager keep serving after the seal, and after the app
exits. Payloads load on either side of it — checked with a DNS redirect, a mount
helper and the homebrew enabler, which cannot do its job without writing kernel
state. That kernel access survives the restore is measured; how it does is not,
since the expectation was that it rode the crossed pipes and would die with them.

### Two build flags that are fatal

Both are still in the source for diagnosis and must not be enabled in anything
that runs on a console you care about.

* Nulling `p_aioinfo` to leak the aio state panics spontaneously, seconds after the
  write, with the app still open.
* Restoring the OIDs through the sysctl window after the pipes are down.
  `restoreOidsSlow()` restores the window through the window, and `aimWindow()`
  steers by moving `arg1` pointers, so restoring `a.arg1` destroys the mechanism
  the next write needs.

If the app is closed without sealing, reboot and send the payload again; the run
takes about three seconds. Suspending the console is not an alternative — nothing
executes while suspended, so `:9021` will not answer and a saved state has nothing
to resume into.

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
(`chain`, `arm`, `locate`, `fast`, `defuse`, `escalate`), skip the handoff
entirely, and close the pipe fds from the payload instead of leaving them to
process exit. `rescue()` still runs on the way out of every one, so each rung is
self-cleaning. `arm` stops before the pipes are created and `locate` after they
exist but before they are crossed.

`--diag` also puts back `holdPipeFiles()` and the flags that call it, neither of
which is in the production payload.

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

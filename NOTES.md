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
4. Puts back what it can on the way out: both pipes' own buffers and sizes, the
   armed aio groups, the parked aio workers, the scratch descriptors, and `eboot`'s
   original segment descriptors. Teardown order matters — see below.
5. Leaves the sysctl OIDs hijacked, because the write window that restores the
   pipes cannot close itself. That is the one residue a reboot clears; see
   [Closing the app](#closing-the-app).

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
is not. `relapse.js` is ~254 KB, leaving under 2 KB of headroom, which is why the
diagnostic code listed near the end of this file is not in it.

## Logging

Every line goes to the sender over the TCP connection, and is also mirrored with
a bare `sendto()` to UDP port 5050 on whichever address sent the payload. The
UDP copy is the one that survives a kernel panic, so it is worth capturing:

```bash
nc -u -l 5050
```

If the mirror cannot be set up the payload says why rather than just reporting that
it is off. The common case is sending the payload from the console itself, through a
payload manager: the peer is then loopback and there is nowhere to mirror to, so send
it from a PC on the same network if you want the panic-surviving copy.

Every line is prefixed `[relapse NNN]` with a sequence number. The loader's TCP
transcript reorders and drops lines when the console dies — one external report had
`kexp shellcode returned` printed before the `Thrd_create` that caused it — and
without a number there is no way to tell a lost line from a late one. With it, the
highest number received is the last step completed and any gap names the step that
died. Every line goes through the synchronous path; two of them used to go through
the framework's buffered `log()` instead, and they were `=== relapse complete ===`
and the final state line, which is why they were the ones missing from transcripts
of runs that panicked.

The last line states whether closing is safe rather than leaving it to inference,
and the teardown summary is derived from what was actually achieved — pipes safe or
possibly still armed, OIDs restored or left hijacked. Three earlier revisions
printed success there without having checked.

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

The check is a file-existence test, so if you know the kernel is clean, deleting
that file clears it.

## Closing the app

Closing YouTube after a jailbreak used to panic the console, and an earlier
revision of this repository shipped an ELF to prevent it. The payload now does
that work itself: it writes both pipes' own buffers and sizes back before it
returns, verified by readback, and the app can be closed normally.

What follows is why that is the fix, what it leaves behind, and the one firmware
where it has been seen not to be enough.

### Measured on 12.60 only

Everything in this section was established on firmware 12.60. Restoring the pipe
buffers is necessary on every firmware, because the state it fixes is the state the
exploit leaves on every firmware. It is only *known* to be sufficient on 12.60.

A 7.61 console (YouTube PPSA01651) ran an earlier revision, sent the seal ELF, got
"both pipes are ordinary again, the app can exit", closed the app and
kernel-panicked. That log pair is worth reading closely, because it separates "the
restore failed" from "something else is left over" — and it says the restore did
its job:

* It ran in restore mode, and read both buffers back equal to what it wrote.
* The 7.61 pipe offsets are correct independently of the offset table. The
  never-written reference pipe shows `count`/`in`/`out` zero, `size` 0x4000 at
  +0x0c and `buffer` NULL at +0x10 — exactly where the table puts them.
* `restoreOids()` ran to completion. At seal time the victim's `buffer` was
  `kbase + 0x3c93f78`, and `0x3c93f78` is that firmware's `walkCounter.addr`,
  the target of the function's last write. Every fast-path write re-aims the
  victim before it lands, so the leftover pointer fingerprints the last write
  performed.
* The pre-seal struct state matches the 12.60 state that survived closing, field
  for field.

So on 7.61 there is a third cause of the close panic, outside the two pipe
structs and outside the sysctl OIDs. It has not been found, and because it is
outside both, doing the restore from the payload rather than from an ELF would not
have prevented it.

That particular report cannot narrow it any further: it was captured with network
logging disabled, so there was no UDP stream, and the TCP-only transcript is lossy
and out of order — it prints `kexp shellcode returned` before the `Thrd_create`
that caused it. Two of the payload's own lines went through the framework's
buffered `log()` rather than the synchronous `write(2)` path, which is why they
were missing; both now go through the synchronous path, and every line carries a
sequence number, so a gap names the step that died instead of leaving it to
guesswork. See [Logging](#logging).

If closing panics your console on some other firmware, re-run with the payload
sent over a raw TCP connection so it mirrors every line to UDP 5050. That
transcript survives the panic and keeps its order, which is what it takes to tell
a failed step from a lost log line.

### What the exploit leaves behind

Fast kernel read/write is built from two pipes. One pipe's `buffer` field is
pointed at the other pipe's `struct pipe`, so a `write()` on the first lands in
the second's fields; the second's `buffer` is then aimed at an arbitrary kernel
address, so a `write()` on it lands anywhere.

The payload undoes that before it returns. It was believed that it could not,
because `kexp` is handed the same two pipe descriptor pairs and `elfldr`'s kernel
access was assumed to ride on the crossing. It does not: `kexp` runs on its own
`pipe2`, set up during the handoff before any teardown runs. An FTP server that
cannot do its job without kernel write answered with its banner after a run that
had already restored both pipes and closed the app.

If the process exits while the pipes are still crossed the kernel tears them down. `pipe_dtor()`
calls `pipe_free_kmem()`, which frees `pipe_buffer.buffer` for `pipe_buffer.size`
bytes — so it hands `kmem_free()` another pipe's struct as though it were a 16 KB
buffer allocation. That is the panic.

### Why it restores the buffers rather than clearing them

Setting `buffer` to NULL looks like the fix and is not. A pipe that has been used
and then had its buffer field cleared sits at `buffer = 0, size = 0`, which is not
a state any live pipe is in and which the teardown has no path for. It also
orphans the real allocation while `amountpipekva` goes on counting it. With
everything else held equal, clearing the buffers kills the console within three
seconds of exit and restoring them does not.

So the payload records both pipes' real buffer addresses before the crossing
overwrites them, writes them back at teardown along with the size, zeroes `count`,
`in` and `out`, and verifies every field by readback. What is left is an ordinary
used-but-empty pipe, which the kernel frees normally.

The allocation is a `pipepair`, not a single `struct pipe`: the second half sits at
`+0x108` and `+0xe0` holds the peer pointer. Both halves matter.

### What the payload still cannot undo

The pipes are restored. The sysctl OIDs are not, and that is forced rather than a
shortcut.

The exploit has two kernel write primitives. The fast one works by aiming the
victim pipe at a target and writing through it, and it exists only while the
master's `buffer` points at the victim's struct — so the write that repairs the
master is the write that destroys the primitive. The slow one goes through a
hijacked sysctl node and never touches the pipes, so it survives any pipe state,
but it exists only because three OID fields were modified: aiming goes through
`kern.smp.cpus`, which needs its `arg1` hijacked and its `kind` writable, and
landing goes through `kern.smp.maxcpus`, which needs its `kind` writable and the
node visible. Restoring those fields needs a write through the window they enable,
so the window cannot close itself.

Hiding `kern.smp.maxcpus` first looked like the way out — the stock kernel does not
expose it, so a wrong `kind` behind an unresolvable node would be harmless. It was
measured and it does not work: a hidden node returns `rv -1` for read and write
alike, with the same write succeeding immediately before and immediately after.

So the payload repairs the pipes with the slow window and leaves the OIDs. The
alternative — repairing the OIDs with the fast window — leaves one pipe armed, and
that is the state that panics. An ELF with kernel read/write from a third source
has neither constraint, which is why one used to ship; it is not needed, and it is
not in this repository any more, because the note file it read is not written by
this configuration.

### A mitigation that was removed

Earlier revisions held the four pipe files at `f_count = 0x10000` so `pipe_dtor()`
could not run at all. That is gone: `holdPipeFiles()` is not in the shipped
payload and nothing there calls it.
Once the buffers are real, `pipe_dtor()` is harmless, and all the hold does is leak
four `struct file` objects past process exit, which the teardown still has to
account for. A full production run with the hold died four seconds after exit; the
same run without it survived.

### Closing the app does not interrupt anything

`:9021` and any payload manager keep serving after the app exits. Payloads load on
either side of the restore — checked with a DNS redirect, a mount helper, an FTP
server and the homebrew enabler, none of which can do their jobs without writing
kernel state. That kernel access survives is measured. It was expected not to, on
the reasoning that it rode the crossed pipes; the reason it does is that `kexp`
runs on its own `pipe2`.

### Two build flags that are fatal

Both are still in the source for diagnosis and must not be enabled in anything
that runs on a console you care about.

* Nulling `p_aioinfo` to leak the aio state panics spontaneously, seconds after the
  write, with the app still open.
* Restoring the OIDs through the sysctl window after the pipes are down.
  `restoreOidsSlow()` restores the window through the window, and `aimWindow()`
  steers by moving `arg1` pointers, so restoring `a.arg1` destroys the mechanism
  the next write needs.

If a run is interrupted before its teardown finishes, the pipes are still crossed
and closing the app will panic; reboot and send the payload again, which takes
about three seconds. Suspending the console is not an alternative — nothing
executes while suspended, so `:9021` will not answer and a saved state has nothing
to resume into.

## What is not in the shipped payload

`relapse.js` is generated, with the comments stripped out; that is what keeps it
under the loader's size limit. It carries no diagnostic code, for two reasons —
there is barely room for any, and some of it is fatal.

Not included:

* a snapshot of the process's kernel-visible state immediately before and after the
  handoff — `p_ucred` and its fields, every `f_cred`, every `td_ucred`, the filedesc
  table, the dynlib syscall range, both pipe buffers — whose diff shows what the
  `kexp` blob changed. That diff is how the blob's fd-table swap was found: 256
  entries at a heap address became 768 entries in a different region.
* a read-only dump of the reclaimed aio waiter arrays, taken while the group still
  points at them.
* `dlsym` probing, and the p2jb-style `f_cred`/`td_ucred` migration.
* `holdPipeFiles()`, which is fatal — see
  [A mitigation that was removed](#a-mitigation-that-was-removed).
* the bisect rungs that stop a run at a stage boundary (`chain`, `arm`, `locate`,
  `fast`, `defuse`, `escalate`), skip the handoff entirely, or close the pipe
  descriptors from the payload instead of leaving them to process exit. `arm` stops
  before the pipes are created and `locate` after they exist but before they are
  crossed.

What the shipped payload does log is under [Logging](#logging): roughly thirty lines
per run, mirrored to UDP 5050.

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
**[P2JB-Y2JB-Porting](https://github.com/matem6/P2JB-Y2JB-Porting)** — the `eboot`
segment preparation, the one-run-per-boot marker discipline, and the post-jailbreak
cred handling.

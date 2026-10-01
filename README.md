# relapse-y2jb

The [Relapse](https://github.com/ntfargo/Relapse-Exploit) PS5 kernel exploit
(`aio_multi_wait` use-after-free), ported from the WebKit browser host to
[Y2JB](https://github.com/Gezine/Y2JB) — the YouTube TV app modded to run
payloads — by **edisnord**. Launch YouTube, send `relapse.js`, get a jailbreak
and an ELF loader on port 9021. No browser, no DNS blocker, no user-guide
redirect.

## Requirements

* PS5 on firmware **7.00 – 13.60** — the range the offset tables cover, not a
  range that has been tested
* Y2JB **1.5 or newer**, restored and working
* A PC on the same network

Tested on firmware 12.60 with Y2JB 1.6 and YouTube app 01.000.030. Where this
README says a behaviour is safe, it means it was measured there.

## Usage

Download `relapse.js` from the
[releases page](https://github.com/edisnord/relapse-y2jb/releases) — it is built
by CI rather than kept in the repository, so what you download is reproducible
from the tag it was built from. `relapse.js.sha256` is attached alongside it.

Then send it like any other Y2JB payload:

```bash
python payload_sender.py <ps5-ip> relapse.js
```

```bash
nc <ps5-ip> 50000 < relapse.js
```

The remote JS server does not always listen on 50000 — see Y2JB's README. Then
load ELFs the usual way:

```bash
python payload_sender.py <ps5-ip> 9021 payload.elf
nc <ps5-ip> 9021 < payload.elf
```

The jailbreak takes about three seconds. Progress is printed to the sender and
mirrored to UDP port 5050 on your machine.

## Closing the app

Just close it. The payload puts both pipes back the way it found them before it
returns, so the app can exit normally — no second file, no extra step, nothing to
remember.

On 12.60 that is measured end to end: the payload reported both buffers restored
and verified by readback, the app was closed with nothing sent to `:9021`, and the
console survived. `:9021` and any payload manager you loaded keep serving
afterwards, so payloads can be loaded before or after closing.

**Measured on 12.60 only.** On a 7.61 console an earlier revision reached the same
pipe state, verified it by readback, and closing still panicked the kernel. That
points to a third cause on that firmware, outside the pipe structs and the sysctl
OIDs, and it has not been found — so it would not be fixed by restoring the
buffers from the payload instead of from an ELF.
[NOTES.md](NOTES.md#measured-on-1260-only) records what that report proves and what
it cannot.

What it costs: the exploit's sysctl write window cannot be closed from inside, so
three `kern.*` nodes stay modified until you reboot. The one that matters is
`kern.smp.cpus`, which returns a kernel address instead of the CPU count. The
payload's last line says so explicitly. Nothing in the post-jailbreak chain cared —
a payload manager, the homebrew enabler, an FTP server and a DNS redirect all ran
afterwards — but software that sizes thread pools by CPU count has not been tested
against it, and a reboot clears it.

Closing without the payload having finished its teardown still panics the console.
The exploit's fast kernel read/write works by pointing one pipe's buffer at the
other pipe's struct; if the process exits in that state the kernel's pipe teardown
frees memory it should not. [NOTES.md](NOTES.md) has the two causes, how they were
found, and why the obvious cleanup makes this worse rather than better.

## Building from source

`relapse.js` is generated — do not edit it. CI builds it from
`src/relapse.template.js` plus the upstream kernel stage and offset tables, which
are vendored as a pinned submodule, and publishes it to the releases page.

See **[BUILD.md](BUILD.md)** for the inputs, the two targets (`y2jb` and
`autoloader`) and what differs between them, the build flags, how to validate a
build, and how to reproduce a published artifact byte for byte.

## Credits

This is a port; nothing here is original work.

* [Relapse](https://github.com/ntfargo/Relapse-Exploit) — the exploit, the
  offset tables and the kernel stage, used verbatim.
* [Y2JB](https://github.com/Gezine/Y2JB) — the host, the loader, and the
  `kexp`/`elfldr` files this hands the kernel to.
* [kexp](https://github.com/ufm42/kexp) — the post-jailbreak shellcode.
* [Luac0re / p2jb](https://github.com/Gezine/Luac0re) and
  [P2JB-Y2JB-Porting](https://github.com/matem6/P2JB-Y2JB-Porting) — where the
  `eboot` segment preparation, the one-run-per-boot marker and the post-jailbreak
  cred handling come from. That port's close-panic work also framed the question
  this one eventually answered.

Each of those credits the people behind it in its own README.

## Licence

MIT — see [LICENSE](LICENSE), matching upstream Relapse. Educational and
security-research use only, on hardware you own. The kernel exploit can hang or
panic the console; reboot before retrying.

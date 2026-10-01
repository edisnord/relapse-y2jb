# relapse-y2jb

The [Relapse](https://github.com/ntfargo/Relapse-Exploit) PS5 kernel exploit
(`aio_multi_wait` use-after-free), ported from the WebKit browser host to
[Y2JB](https://github.com/Gezine/Y2JB) — the YouTube TV app modded to run
payloads. Launch YouTube, send `relapse.js`, get a jailbreak and an ELF loader
on port 9021. No browser, no DNS blocker, no user-guide redirect.

## Requirements

* PS5 on firmware **7.00 – 13.60**
* Y2JB **1.5 or newer**, restored and working
* A PC on the same network

Tested on firmware 12.60 with Y2JB 1.6 and YouTube app 01.000.030.

## Usage

Send it like any other Y2JB payload:

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

Send the seal to port 9021, then close YouTube normally:

```bash
nc <ps5-ip> 9021 < seal/pipeclean.elf
```

The console survives. `:9021` and any payload manager you loaded keep serving
afterwards, so payloads can be loaded on either side of the seal.

The seal needs the pipe addresses the exploit used, and it reads them from a
note file the payload writes — there is nothing to copy by hand. The payload's
last line reminds you and prints what it wrote.

**Without the seal, closing the app panics the console.** The exploit's fast
kernel read/write works by pointing one pipe's buffer at the other pipe's
struct; if the process exits in that state the kernel's pipe teardown frees
memory it should not. The seal puts each pipe's own buffer and size back.
[NOTES.md](NOTES.md) has the two causes, how they were found, and why the
obvious cleanup makes this worse rather than better.

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
panic the console; reboot before retrying. Closing the app without sealing panics
it too — see above.

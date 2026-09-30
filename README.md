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

## Known limitation

**Do not close the YouTube app after jailbreaking.** Exiting the process panics
the console — immediate black screen. Leave the app open. If you do close it,
reboot and send the payload again — the whole run takes about three seconds.

This is not specific to the port. Hardware bisecting puts the trigger on the
pipe crossing that creates the exploit's fast kernel read/write primitive — a
run that does the whole aio race and stops before crossing survives the close,
and one that crosses does not. Neither the payload's own cleanup nor a cleanup
ELF with kernel read/write of its own prevents it.
[NOTES.md](NOTES.md) has what was established, what was exonerated, and two
earlier conclusions that turned out to be instrumentation artifacts.

## Credits

This is a port; nothing here is original work.

* [Relapse](https://github.com/ntfargo/Relapse-Exploit) — the exploit, the
  offset tables and the kernel stage, used verbatim.
* [Y2JB](https://github.com/Gezine/Y2JB) — the host, the loader, and the
  `kexp`/`elfldr` files this hands the kernel to.
* [kexp](https://github.com/ufm42/kexp) — the post-jailbreak shellcode.
* [Luac0re / p2jb](https://github.com/Gezine/Luac0re) and
  [P2JB-Y2JB-Porting](https://github.com/matem6/P2JB-Y2JB-Porting) — where the
  `fhold`/`eboot` preparation, the one-run-per-boot marker and the post-jailbreak
  cred handling come from.

Each of those credits the people behind it in its own README.

## Licence

MIT — see [LICENSE](LICENSE), matching upstream Relapse. Educational and
security-research use only, on hardware you own. The kernel exploit can hang or
panic the console; reboot before retrying.

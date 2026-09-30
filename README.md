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

This is not specific to the port and the payload's own cleanup does not prevent
it. [NOTES.md](NOTES.md) has the hardware investigation that ruled out
everything else.

## Credits

* [Relapse](https://github.com/ntfargo/Relapse-Exploit) — ntfargo and the
  authors it credits: the exploit, the offset tables and the kernel stage this
  port runs verbatim.
* [Y2JB](https://github.com/Gezine/Y2JB) — Gezine: the host, the loader, and the
  `kexp`/`elfldr` files this hands the kernel to.
* [kexp](https://github.com/ufm42/kexp) — ufm42.
* [p2jb / Luac0re](https://github.com/Gezine/Luac0re) — Gezine, cheburek3000,
  and [matem6's Y2JB port](https://github.com/matem6/P2JB-Y2JB-Porting) of it.

Full credit lists are relayed in [NOTES.md](NOTES.md).

## Licence

MIT — see [LICENSE](LICENSE), matching upstream Relapse. Educational and
security-research use only, on hardware you own. The kernel exploit can hang or
panic the console; reboot before retrying.

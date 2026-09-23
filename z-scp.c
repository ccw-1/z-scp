/*
 * z-scp.c  —  pax-stream file transfer to/from z/OS with EBCDIC/tag handling
 *
 * Usage:
 *   z-scp [-r] [--dry-run] [--verify] [--meta] [--meta-file F] <source> <destination>
 *
 * Direction is inferred from the arguments:
 *   upload:   z-scp localfile       user@host:/remote/path
 *   download: z-scp user@host:/remote/path  localfile
 *
 * Transport: all transfers use "ssh user@host /bin/pax ..." with a pax archive
 * stream over stdin/stdout.  No sftp, no chtag — file tagging is handled
 * natively via the ZOS.taginfo pax extended header, which z/OS pax -r reads
 * and applies automatically on extraction.
 *
 * Single-file / recursive upload:
 *   1. Detect file encoding (EBCDIC-1047 / ISO-8859-1 / binary) from content.
 *   2. Build a pax archive in memory:
 *      - optional 'g' global header with ZOS.extattr / ZOS.useraudit /
 *        ZOS.auditoraudit if the meta file carries non-default values.
 *      - 'x' extended header with "ZOS.taginfo=<is_text> <ccsid>" per file.
 *      - ustar file header + content (1047 pre-converted to 819; others as-is).
 *   3. Pipe the archive to: ssh user@host "/bin/pax -r -p p"
 *      z/OS SSH AUTOCVT applies a2e[] to stdin bytes; pax_write() pre-applies
 *      e2a[] so the net effect is identity and z/OS pax sees a plain ASCII stream.
 *
 * Single-file / recursive download:
 *   1. Run: ssh user@host "/bin/pax -w -x pax <files>" and read stdout.
 *      z/OS SSH AUTOCVT applies e2a[] to stdout bytes; pipe_read_block() applies
 *      a2e[] to undo it, recovering the original on-disk bytes.
 *   2. Parse the pax archive: ZOS.taginfo xhdr gives the remote CCSID;
 *      ZOS.extattr / ZOS.useraudit / ZOS.auditoraudit from 'g' headers are
 *      captured and written to the meta file if --meta / --meta-file is given.
 *   3. Write files locally; convert 1047→819 if the remote tag is 1047.
 *
 * Meta file (--meta / --meta-file):
 *   A JSON sidecar that records z/OS-specific per-file attributes that have no
 *   portable equivalent: CCSID, tag state, extattr flags, and audit flags.
 *   Written on download; read on upload to restore the original remote state.
 *   ZOS.filefmt is parsed but not stored (always "not" for HFS/zFS files).
 *
 * Build:  gcc -std=c11 -Wall -Wextra -O2 -o z-scp z-scp.c
 */
#ifdef __MVS__
#error This is meant to be run on a normal posix platform
#endif

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

/* Tunable safety limits */
#define XHDR_MAX_BYTES   (1u << 20)   /* 1 MiB cap for a single xhdr blob */
#define SMART_MAX_BYTES  (16u << 20)  /* 16 MiB cap for --smart re-scan */
#define META_MAX_BYTES   (16u << 20)  /* 16 MiB cap for meta JSON (read side) */
#define CACHE_MAX_BYTES  65536

/* =========================================================================
 * Conversion tables  (from cat2.c — round-trip verified)
 * ====================================================================== */

/* ISO-8859-1 (CCSID 819) → EBCDIC-1047  (needed for EBCDIC PAX headers) */
static const unsigned char a2e[256] = {
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x15, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26,
    0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f, 0x40, 0x5a, 0x7f, 0x7b,
    0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e,
    0x4c, 0x7e, 0x6e, 0x6f, 0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xad, 0xe0, 0xbd, 0x5f, 0x6d,
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92,
    0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
    0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0xa1, 0x07, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
    0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b,
    0x04, 0x14, 0x3e, 0xff, 0x41, 0xaa, 0x4a, 0xb1, 0x9f, 0xb2, 0x6a, 0xb5,
    0xbb, 0xb4, 0x9a, 0x8a, 0xb0, 0xca, 0xaf, 0xbc, 0x90, 0x8f, 0xea, 0xfa,
    0xbe, 0xa0, 0xb6, 0xb3, 0x9d, 0xda, 0x9b, 0x8b, 0xb7, 0xb8, 0xb9, 0xab,
    0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9e, 0x68, 0x74, 0x71, 0x72, 0x73,
    0x78, 0x75, 0x76, 0x77, 0xac, 0x69, 0xed, 0xee, 0xeb, 0xef, 0xec, 0xbf,
    0x80, 0xfd, 0xfe, 0xfb, 0xfc, 0xba, 0xae, 0x59, 0x44, 0x45, 0x42, 0x46,
    0x43, 0x47, 0x9c, 0x48, 0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,
    0x8c, 0x49, 0xcd, 0xce, 0xcb, 0xcf, 0xcc, 0xe1, 0x70, 0xdd, 0xde, 0xdb,
    0xdc, 0x8d, 0x8e, 0xdf,
};


/* EBCDIC-1047 → ISO-8859-1 (CCSID 819) — derived from a2e, round-trip verified */
static const unsigned char e2a[256] = {
    /* 00 */ 0x00, 0x01, 0x02, 0x03, 0x9c, 0x09, 0x86, 0x7f, 0x97, 0x8d, 0x8e, 0x0b,
    /* 0c */ 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x9d, 0x0a, 0x08, 0x87,
    /* 18 */ 0x18, 0x19, 0x92, 0x8f, 0x1c, 0x1d, 0x1e, 0x1f, 0x80, 0x81, 0x82, 0x83,
    /* 24 */ 0x84, 0x85, 0x17, 0x1b, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x05, 0x06, 0x07,
    /* 30 */ 0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, 0x98, 0x99, 0x9a, 0x9b,
    /* 3c */ 0x14, 0x15, 0x9e, 0x1a, 0x20, 0xa0, 0xe2, 0xe4, 0xe0, 0xe1, 0xe3, 0xe5,
    /* 48 */ 0xe7, 0xf1, 0xa2, 0x2e, 0x3c, 0x28, 0x2b, 0x7c, 0x26, 0xe9, 0xea, 0xeb,
    /* 54 */ 0xe8, 0xed, 0xee, 0xef, 0xec, 0xdf, 0x21, 0x24, 0x2a, 0x29, 0x3b, 0x5e,
    /* 60 */ 0x2d, 0x2f, 0xc2, 0xc4, 0xc0, 0xc1, 0xc3, 0xc5, 0xc7, 0xd1, 0xa6, 0x2c,
    /* 6c */ 0x25, 0x5f, 0x3e, 0x3f, 0xf8, 0xc9, 0xca, 0xcb, 0xc8, 0xcd, 0xce, 0xcf,
    /* 78 */ 0xcc, 0x60, 0x3a, 0x23, 0x40, 0x27, 0x3d, 0x22, 0xd8, 0x61, 0x62, 0x63,
    /* 84 */ 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0xab, 0xbb, 0xf0, 0xfd, 0xfe, 0xb1,
    /* 90 */ 0xb0, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xaa, 0xba,
    /* 9c */ 0xe6, 0xb8, 0xc6, 0xa4, 0xb5, 0x7e, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    /* a8 */ 0x79, 0x7a, 0xa1, 0xbf, 0xd0, 0x5b, 0xde, 0xae, 0xac, 0xa3, 0xa5, 0xb7,
    /* b4 */ 0xa9, 0xa7, 0xb6, 0xbc, 0xbd, 0xbe, 0xdd, 0xa8, 0xaf, 0x5d, 0xb4, 0xd7,
    /* c0 */ 0x7b, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xad, 0xf4,
    /* cc */ 0xf6, 0xf2, 0xf3, 0xf5, 0x7d, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    /* d8 */ 0x51, 0x52, 0xb9, 0xfb, 0xfc, 0xf9, 0xfa, 0xff, 0x5c, 0xf7, 0x53, 0x54,
    /* e4 */ 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0xb2, 0xd4, 0xd6, 0xd2, 0xd3, 0xd5,
    /* f0 */ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xb3, 0xdb,
    /* fc */ 0xdc, 0xd9, 0xda, 0x9f,
};

/* =========================================================================
 * Detection tables  (from tagfile.c verbatim)
 * ====================================================================== */

static const char ebcdic_valid[256] = {
    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
};

static const char ascii_valid[256] = {
    0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static const char utf8pat[256] = {
    9, 9, 9, 9, 9, 9, 9, 0, 0, 0, 0, 9, 0, 0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 0, 9, 9, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 9, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 9, 9, 9, 9, 9, 9, 9, 9,
};

/* =========================================================================
 * PAX header encoding
 * ====================================================================== */

typedef enum { PAX_ASCII = 0, PAX_EBCDIC = 1 } pax_enc_t;

/* Probed pax-header encoding for the current host (see get_host_enc).
 * Diagnostic only: transfers pin PAX_EBCDIC with explicit
 * _BPXK_AUTOCVT=ON (see pipe_read_block), so a mis-probe can never corrupt
 * data.  Defaults to EBCDIC (z/OS) when no probe ran (e.g. --dry-run). */
static pax_enc_t g_pax_enc = PAX_EBCDIC;

/* =========================================================================
 * ssh subprocess helpers (no local shell — fixes command injection)
 *
 * Previously every transfer built "ssh ... '...'" strings for popen()/
 * system(), so a crafted host/path could execute arbitrary local commands.
 * These helpers fork+exec ssh directly: host travels as a single argv
 * element (never interpreted by /bin/sh).  The remote command string is
 * still interpreted by the *remote* shell, so remote paths are
 * single-quote escaped by ssh_quote_append().
 * ====================================================================== */

/* Append s to out (size outsz, *off = current len) wrapped in single quotes,
 * escaping embedded single quotes as '"'"'.  Returns 0 ok, -1 truncated. */
static int ssh_quote_append(char *out, size_t outsz, size_t *off,
                            const char *s) {
    size_t o = *off;
    if (o + 1 >= outsz) return -1;
    out[o++] = '\'';
    for (; *s; s++) {
        if (*s == '\'') {
            if (o + 4 >= outsz) return -1;
            memcpy(out + o, "'\"'\"'", 4); o += 4;
        } else {
            if (o + 1 >= outsz) return -1;
            out[o++] = *s;
        }
    }
    if (o + 1 >= outsz) return -1;
    out[o++] = '\'';
    out[o] = '\0';
    *off = o;
    return 0;
}

/* Reject hosts that could smuggle ssh options.  Host travels as one argv
 * element so spaces/quotes are harmless, but a leading '-' would be parsed
 * as flags by ssh. */
static int host_is_safe(const char *host) {
    if (!host || !*host) return 0;
    if (host[0] == '-') return 0;
    if (strchr(host, '\n') || strchr(host, '\r')) return 0;
    return 1;
}

/* Spawn "ssh -o BatchMode=yes <host> <remote_cmd>".
 * direction: 'r' → return FILE* reading child's stdout; 'w' → writing to
 * child's stdin.  *pid_out receives the child pid for ssh_wait().
 * Returns NULL on failure. */
static FILE *ssh_spawn(const char *host, const char *remote_cmd, char direction,
                       pid_t *pid_out) {
    if (!host_is_safe(host)) {
        fprintf(stderr, "z-scp: refusing unsafe ssh host '%s'\n", host);
        return NULL;
    }
    int fds[2];
    if (pipe(fds) != 0) {
        fprintf(stderr, "z-scp: pipe: %s\n", strerror(errno));
        return NULL;
    }
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "z-scp: fork: %s\n", strerror(errno));
        close(fds[0]); close(fds[1]);
        return NULL;
    }
    if (pid == 0) {
        /* child */
        if (direction == 'r') {
            dup2(fds[1], STDOUT_FILENO);
        } else {
            dup2(fds[0], STDIN_FILENO);
        }
        close(fds[0]); close(fds[1]);
        execlp("ssh", "ssh", "-o", "BatchMode=yes", host, remote_cmd,
               (char *)NULL);
        _exit(127);
    }
    /* parent */
    FILE *fp;
    if (direction == 'r') {
        close(fds[1]);
        fp = fdopen(fds[0], "r");
    } else {
        close(fds[0]);
        fp = fdopen(fds[1], "w");
    }
    if (!fp) {
        close(direction == 'r' ? fds[0] : fds[1]);
        return NULL;
    }
    *pid_out = pid;
    return fp;
}

/* fclose() the stream and wait for the child; returns the raw wait status
 * (like pclose: use WIFEXITED/WEXITSTATUS on success, -1 on error). */
static int ssh_wait(FILE *fp, pid_t pid) {
    if (fp) fclose(fp);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    return status;
}

/* Run a remote command whose output we discard, streaming-side equivalent
 * of system() but without a local shell (used by --verify). */
static int ssh_run_discard(const char *host, const char *remote_cmd) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execlp("ssh", "ssh", "-o", "BatchMode=yes", host, remote_cmd,
               (char *)NULL);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    return status;
}

/* =========================================================================
 * Host capability cache  (~/.zscp_hosts.json)
 * ====================================================================== */

static void json_escape(const char *s, char *buf, size_t bufsz);

static void cache_path(char *buf, size_t sz) {
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(buf, sz, "%s/.zscp_hosts.json", home);
}

/* Read pax_encoding for host from cache.
 * Returns PAX_ASCII, PAX_EBCDIC, or -1 if not found. */
static int cache_read(const char *host) {
    char path[512];
    cache_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);
    if (fsz <= 0 || fsz > CACHE_MAX_BYTES) { fclose(f); return -1; }
    char *buf = malloc(fsz + 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, fsz, f) != (size_t)fsz) { free(buf); fclose(f); return -1; }
    fclose(f);
    buf[fsz] = '\0';

    /* Exact key match: "host" must be followed by optional space + ':' so
     * that host "pok" can never match an entry for "pok56". */
    char needle[300];
    snprintf(needle, sizeof(needle), "\"%s\"", host);
    size_t nlen = strlen(needle);
    char *p = buf;
    int found = 0;
    while ((p = strstr(p, needle)) != NULL) {
        const char *t = p + nlen;
        while (*t == ' ' || *t == '\t') t++;
        if (*t == ':') { found = 1; break; }
        p += nlen;
    }
    if (!found) { free(buf); return -1; }
    char *q = strstr(p, "\"pax_encoding\"");
    if (!q || q - p > 512) { free(buf); return -1; }
    q = strchr(q, ':');
    if (!q) { free(buf); return -1; }
    q++;
    while (*q == ' ' || *q == '\t') q++;
    if (*q != '"') { free(buf); return -1; }
    q++;
    int result = -1;
    if (strncmp(q, "ebcdic", 6) == 0) result = PAX_EBCDIC;
    else if (strncmp(q, "ascii",  5) == 0) result = PAX_ASCII;
    free(buf);
    return result;
}

/* Write or update pax_encoding for host in the cache. */
static void cache_write(const char *host, pax_enc_t enc) {
    char path[512];
    cache_path(path, sizeof(path));

    char *existing = NULL;
    long fsz = 0;
    FILE *f = fopen(path, "r");
    if (f) {
        fseek(f, 0, SEEK_END);
        fsz = ftell(f);
        rewind(f);
        if (fsz > 0 && fsz < CACHE_MAX_BYTES) {
            existing = malloc(fsz + 1);
            if (existing) {
                if (fread(existing, 1, fsz, f) != (size_t)fsz) {
                    free(existing); existing = NULL;
                } else { existing[fsz] = '\0'; }
            }
        }
        fclose(f);
    }

    time_t now = time(NULL);
    struct tm *tm_utc = gmtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm_utc);

    char eschost[512];
    json_escape(host, eschost, sizeof(eschost));
    char entry[1024];
    if (snprintf(entry, sizeof(entry),
             "  \"%s\": { \"pax_encoding\": \"%s\", \"detected\": \"%s\" }",
             eschost, enc == PAX_EBCDIC ? "ebcdic" : "ascii", ts)
            >= (int)sizeof(entry)) {
        free(existing);
        return; /* host too long; don't write a truncated entry */
    }

    f = fopen(path, "w");
    if (!f) { free(existing); return; }

    if (existing && fsz > 2) {
        char needle[300];
        snprintf(needle, sizeof(needle), "\"%s\"", host);
        char *p = strstr(existing, needle);
        if (p) {
            /* rewrite file, replacing this host's entry */
            fprintf(f, "{\n");
            char *scan = existing;
            while (*scan && (*scan == '{' || *scan == '\n' || *scan == ' ')) scan++;
            int first = 1;
            while (*scan && *scan != '}') {
                if (*scan != '"') { scan++; continue; }
                char *key_start = scan;
                char *colon = strchr(scan + 1, ':');
                if (!colon) break;
                char *inner = strchr(colon, '{');
                if (!inner) break;
                char *inner_end = strchr(inner, '}');
                if (!inner_end) break;
                char *entry_end = inner_end + 1;
                char key[256] = {0};
                size_t klen = colon - scan - 1;
                if (klen > 1 && klen < sizeof(key))
                    memcpy(key, scan + 1, klen - 1);
                if (strcmp(key, host) != 0) {
                    if (!first) fprintf(f, ",\n");
                    fwrite(key_start, 1, entry_end - key_start, f);
                    first = 0;
                }
                scan = entry_end;
                while (*scan == ',' || *scan == '\n' || *scan == ' ') scan++;
            }
            if (!first) fprintf(f, ",\n");
            fprintf(f, "%s\n}\n", entry);
        } else {
            /* append new host to existing object */
            char *end = strrchr(existing, '}');
            if (end) {
                char *start = existing;
                while (*start == '{' || *start == '\n' || *start == ' ') start++;
                if (start >= end)
                    fprintf(f, "{\n%s\n}\n", entry);
                else {
                    fwrite(existing, 1, end - existing, f);
                    fprintf(f, ",\n%s\n}\n", entry);
                }
            } else {
                fprintf(f, "{\n%s\n}\n", entry);
            }
        }
    } else {
        fprintf(f, "{\n%s\n}\n", entry);
    }
    fclose(f);
    free(existing);
}

/* =========================================================================
 * Host probe: detect whether remote pax uses ASCII or EBCDIC headers
 * ====================================================================== */

/* Check magic bytes at offset 257 to determine PAX header encoding.
 * EBCDIC-1047: u=0xe4 s=0xa2 t=0xa3 a=0x81 r=0x99 */
static pax_enc_t detect_magic(const unsigned char hdr[512]) {
    if (memcmp(hdr + 257, "ustar", 5) == 0) return PAX_ASCII;
    static const unsigned char ebcdic_ustar[5] = {0xe4, 0xa2, 0xa3, 0x81, 0x99};
    if (memcmp(hdr + 257, ebcdic_ustar, 5) == 0) return PAX_EBCDIC;
    return PAX_ASCII; /* unknown — default safe */
}

/* Ask remote host to produce a tiny PAX archive, inspect its magic field.
 * Uses a mktemp-created remote file (no predictable /tmp name) and no
 * local shell: host travels as a single ssh argv element.
 * Returns PAX_ASCII/PAX_EBCDIC, or -1 when the probe itself failed
 * (caller falls back to EBCDIC without caching). */
static int probe_host(const char *host) {
    fprintf(stderr, "z-scp: probing PAX header encoding for %s...\n", host);

    static const char remote_cmd[] =
        "unset _BPXK_AUTOCVT; "
        "T=$(/bin/mktemp /tmp/__zscp_probe_XXXXXX) || exit 1; "
        "/bin/echo x>\"$T\" && "
        "/bin/pax -w -x pax \"$T\"; rc=$?; "
        "/bin/rm -f \"$T\"; exit $rc";

    pid_t pid = -1;
    FILE *p = ssh_spawn(host, remote_cmd, 'r', &pid);
    if (!p) {
        fprintf(stderr, "z-scp: probe spawn failed\n");
        return -1;
    }

    unsigned char hdr[512];
    size_t got = 0;
    while (got < 512) {
        size_t n = fread(hdr + got, 1, 512 - got, p);
        if (n == 0) break;
        got += n;
    }
    int status = ssh_wait(p, pid);

    if (got < 512 || status != 0) {
        fprintf(stderr, "z-scp: probe failed (got %zu bytes, status %d)\n",
                got, status);
        return -1;
    }

    pax_enc_t enc = detect_magic(hdr);
    fprintf(stderr, "z-scp: %s uses %s PAX headers\n",
            host, enc == PAX_EBCDIC ? "EBCDIC" : "ASCII");
    return (int)enc;
}

/* Return cached or freshly probed PAX encoding for host.
 * Unprobed/unreachable hosts fall back to EBCDIC (z/OS) without caching,
 * so a transient ssh failure can never poison the cache. */
static pax_enc_t get_host_enc(const char *host, int reprobe_flag) {
    if (!reprobe_flag) {
        int cached = cache_read(host);
        if (cached >= 0) {
            fprintf(stderr, "z-scp: cached PAX encoding for %s: %s\n",
                    host, cached == PAX_EBCDIC ? "ebcdic" : "ascii");
            return (pax_enc_t)cached;
        }
    }
    int probed = probe_host(host);
    if (probed < 0) {
        fprintf(stderr, "z-scp: probe failed for %s, assuming EBCDIC\n", host);
        return PAX_EBCDIC;
    }
    cache_write(host, (pax_enc_t)probed);
    return (pax_enc_t)probed;
}

/* =========================================================================
 * Detection (from tagfile.c logic)
 * ====================================================================== */

typedef struct {
    size_t ebcdic_cnt;
    size_t total_ebcdic;
    size_t ascii_cnt;
    size_t total_ascii;
    int    utf8_st;
    int    utf8_format_error;
} cp_state_t;

static void scan_chunk(const unsigned char *buf, size_t n, cp_state_t *s) {
    /* EBCDIC scoring */
    for (size_t i = 0; i < n; i++) {
        if (ebcdic_valid[(unsigned char)buf[i]]) s->ebcdic_cnt++;
        s->total_ebcdic++;
    }
    /* ASCII scoring */
    for (size_t i = 0; i < n; i++) {
        if (ascii_valid[(unsigned char)buf[i]]) s->ascii_cnt++;
        s->total_ascii++;
    }
    /* UTF-8 state machine */
    enum { onebyte=1, twobyte0, threebyte0, threebyte1,
           fourbyte0, fourbyte1, fourbyte2, bad } st;
    st = s->utf8_st ? s->utf8_st : onebyte;
    for (size_t i = 0; i < n && st != bad; i++) {
        int p = utf8pat[(unsigned char)buf[i]];
        switch (st) {
        case onebyte:
            if      (p == 9 || p == 1) st = bad;
            else if (p == 2)           st = twobyte0;
            else if (p == 3)           st = threebyte0;
            else if (p == 4)           st = fourbyte0;
            break;
        case twobyte0:   st = (p == 1) ? onebyte    : bad; break;
        case threebyte0: st = (p == 1) ? threebyte1 : bad; break;
        case threebyte1: st = (p == 1) ? onebyte    : bad; break;
        case fourbyte0:  st = (p == 1) ? fourbyte1  : bad; break;
        case fourbyte1:  st = (p == 1) ? fourbyte2  : bad; break;
        case fourbyte2:  st = (p == 1) ? onebyte    : bad; break;
        default:         st = bad;
        }
    }
    if (st == bad) s->utf8_format_error = 1;
    s->utf8_st = st;
}

/* Returns detected CCSID: 1047, 819, or 65535 (binary).
 * *is_text is set to 1 if tagged text, 0 if binary/untagged. */
static int detect_ccsid(const char *path, int *is_text) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "z-scp: open %s: %s\n", path, strerror(errno)); return -1; }

    cp_state_t s;
    memset(&s, 0, sizeof(s));
    unsigned char chunk[8192];
    ssize_t n;
    while ((n = read(fd, chunk, sizeof(chunk))) > 0)
        scan_chunk(chunk, (size_t)n, &s);
    close(fd);

    if (s.total_ebcdic == 0) { *is_text = 0; return 65535; } /* empty */

    /* exact match → definitive text */
    if (s.ebcdic_cnt == s.total_ebcdic) { *is_text = 1; return 1047; }
    if (s.ascii_cnt  == s.total_ascii)  { *is_text = 1; return 819;  }
    /* valid UTF-8 that passes ascii check → treat as 819 */
    if (s.ascii_cnt > 0 && !s.utf8_format_error && s.utf8_st == 1) {
        *is_text = 1; return 819;
    }
    /* Near match (within 5% of perfect, i.e. score > ~95.2%): probable
     * text but not pure — e.g. text with a few stray bytes.  The 105/100
     * factors are a 5% *tolerance*, not a 5%-of-total threshold: rewriting
     * this as cnt*20 > total would misclassify virtually every binary
     * (random data scores ~40-50% on both tables) as text.  Mid-range
     * scores correctly fall through to 65535/binary below. */
    if (s.ebcdic_cnt > 0 && (s.ebcdic_cnt * 105) / (s.total_ebcdic * 100) > 0) {
        *is_text = 0; return 1047;
    }
    if (s.ascii_cnt > 0  && (s.ascii_cnt  * 105) / (s.total_ascii  * 100) > 0) {
        *is_text = 0; return 819;
    }
    *is_text = 0; return 65535;
}

/* =========================================================================
 * Meta file — per-file z/OS attribute record
 *
 * Written on download, read on upload.  Plain JSON, no external parser needed.
 * Format (all fields written on download; only non-default extattr/audit
 * fields are restored on upload):
 *
 *   {
 *     "version": 1,
 *     "host": "pok56",
 *     "remote_root": "/u/ccw/proj",
 *     "local_root":  "proj",
 *     "files": {
 *       "src/main.c": {
 *         "ccsid": 819, "tag": "on", "mode": "0644", "mtime": 1234567890
 *       },
 *       "bin/myprog": {
 *         "ccsid": 65535, "tag": "off", "mode": "0755", "mtime": 1234567890,
 *         "extattr": "--s-",
 *         "useraudit": "fff", "auditoraudit": "---"
 *       }
 *     }
 *   }
 *
 * ZOS.extattr field positions: [apf][progctl][shareAS][reserved]
 * Only stored when != "----".
 * useraudit / auditoraudit only stored when != defaults ("fff" / "---").
 * ====================================================================== */

/* Per-file metadata record (in-memory) */
typedef struct {
    char  rel_path[4096];    /* key: path relative to transfer root */
    int   ccsid;             /* 819, 1047, 65535(binary), 0(unknown) */
    int   tag_on;            /* 1 = T=on (ZOS.taginfo present), 0 = T=off */
    mode_t mode;             /* permission bits */
    time_t mtime;            /* modification time */
    char  extattr[5];        /* "----", "--s-", etc.  NUL-terminated */
    char  useraudit[8];      /* e.g. "fff" */
    char  auditoraudit[8];   /* e.g. "---" */
} meta_entry_t;

/* Growable array of meta entries */
typedef struct {
    meta_entry_t *entries;
    size_t        n, cap;
} meta_db_t;

static void meta_db_init(meta_db_t *db) {
    db->entries = NULL; db->n = db->cap = 0;
}

static meta_entry_t *meta_db_add(meta_db_t *db) {
    if (db->n == db->cap) {
        size_t ncap = db->cap ? db->cap * 2 : 64;
        meta_entry_t *nn = realloc(db->entries, ncap * sizeof(meta_entry_t));
        if (!nn) return NULL;
        db->entries = nn;
        db->cap = ncap;
    }
    meta_entry_t *e = &db->entries[db->n++];
    memset(e, 0, sizeof(*e));
    strcpy(e->extattr,      "----");
    strcpy(e->useraudit,    "fff");
    strcpy(e->auditoraudit, "---");
    return e;
}

/* Find entry by relative path; returns NULL if not found. */
static meta_entry_t *meta_db_find(meta_db_t *db, const char *rel_path) {
    for (size_t i = 0; i < db->n; i++)
        if (strcmp(db->entries[i].rel_path, rel_path) == 0)
            return &db->entries[i];
    return NULL;
}

static void meta_db_free(meta_db_t *db) {
    free(db->entries);
    db->entries = NULL; db->n = db->cap = 0;
}

/*
 * json_escape: write s into buf (size bufsz) with JSON string escaping.
 * Handles quotes, backslashes and C0 controls (\n etc.); other bytes
 * pass through.  Truncates safely on overflow.
 */
static void json_escape(const char *s, char *buf, size_t bufsz) {
    size_t o = 0;
    static const char hexd[] = "0123456789abcdef";
    for (; *s && o + 1 < bufsz; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            if (o + 2 >= bufsz) break;
            buf[o++] = '\\'; buf[o++] = (char)c;
        } else if (c < 0x20) {
            if (o + 6 >= bufsz) break;
            buf[o++] = '\\'; buf[o++] = 'u'; buf[o++] = '0'; buf[o++] = '0';
            buf[o++] = hexd[(c >> 4) & 0xf]; buf[o++] = hexd[c & 0xf];
        } else {
            buf[o++] = (char)c;
        }
    }
    buf[o] = '\0';
}

/*
 * meta_write: serialise meta_db to a JSON file, atomically (write to a
 * sibling temp file, fsync, rename) so a crash never leaves a truncated
 * sidecar behind.
 * header fields (host, remote_root, local_root) are passed directly.
 */
static int meta_write(const char *path, const meta_db_t *db,
                      const char *host, const char *remote_root,
                      const char *local_root) {
    char tmp[4200];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid())
            >= (int)sizeof(tmp)) {
        fprintf(stderr, "z-scp: meta path too long: %s\n", path);
        return -1;
    }
    FILE *f = fopen(tmp, "w");
    if (!f) {
        fprintf(stderr, "z-scp: cannot write meta file %s: %s\n",
                tmp, strerror(errno));
        return -1;
    }

    char esc[4096];
    fprintf(f, "{\n");
    fprintf(f, "  \"version\": 1,\n");
    json_escape(host,        esc, sizeof(esc)); fprintf(f, "  \"host\": \"%s\",\n", esc);
    json_escape(remote_root, esc, sizeof(esc)); fprintf(f, "  \"remote_root\": \"%s\",\n", esc);
    json_escape(local_root,  esc, sizeof(esc)); fprintf(f, "  \"local_root\": \"%s\",\n", esc);
    fprintf(f, "  \"files\": {\n");

    for (size_t i = 0; i < db->n; i++) {
        const meta_entry_t *e = &db->entries[i];
        json_escape(e->rel_path, esc, sizeof(esc));
        fprintf(f, "    \"%s\": {\n", esc);
        fprintf(f, "      \"ccsid\": %d,\n", e->ccsid);
        fprintf(f, "      \"tag\": \"%s\",\n", e->tag_on ? "on" : "off");
        fprintf(f, "      \"mode\": \"%04o\",\n", (unsigned)(e->mode & 07777));
        fprintf(f, "      \"mtime\": %lld", (long long)e->mtime);
        /* optional fields — only emit when non-default */
        if (strcmp(e->extattr, "----") != 0)
            fprintf(f, ",\n      \"extattr\": \"%s\"", e->extattr);
        if (strcmp(e->useraudit, "fff") != 0)
            fprintf(f, ",\n      \"useraudit\": \"%s\"", e->useraudit);
        if (strcmp(e->auditoraudit, "---") != 0)
            fprintf(f, ",\n      \"auditoraudit\": \"%s\"", e->auditoraudit);
        fprintf(f, "\n    }%s\n", (i + 1 < db->n) ? "," : "");
    }

    fprintf(f, "  }\n}\n");
    if (fflush(f) != 0) {
        fprintf(stderr, "z-scp: cannot flush meta file %s: %s\n",
                tmp, strerror(errno));
        fclose(f);
        unlink(tmp);
        return -1;
    }
    int mfd = fileno(f);
    if (mfd >= 0) fsync(mfd);
    fclose(f);
    if (rename(tmp, path) != 0) {
        fprintf(stderr, "z-scp: cannot publish meta file %s: %s\n",
                path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

/*
 * json_str_val: locate "key": "VALUE" in buf and copy VALUE into out (outsz).
 * Returns 1 on success, 0 if not found.
 */
static int json_str_val(const char *buf, const char *key,
                        char *out, size_t outsz) {
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(buf, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p != '"') return 0;
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < outsz) {
        if (*p == '\\') p++;   /* skip escape prefix */
        out[o++] = *p++;
    }
    out[o] = '\0';
    return 1;
}

/*
 * json_int_val: locate "key": NUMBER in buf and return the integer.
 * Returns def if not found.
 */
static long long json_int_val(const char *buf, const char *key, long long def) {
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(buf, needle);
    if (!p) return def;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == '-' || (*p >= '0' && *p <= '9')) return strtoll(p, NULL, 10);
    return def;
}

/*
 * meta_read: parse a JSON meta file into db.
 * We do not depend on a full JSON parser — the file is our own output so the
 * structure is predictable.  We scan for "rel_path": { ... } blocks.
 */
static int meta_read(const char *path, meta_db_t *db) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;   /* non-fatal: caller falls back to auto-detect */

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);
    if (fsz <= 0 || fsz > (long)META_MAX_BYTES) { fclose(f); return -1; }

    char *buf = malloc(fsz + 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, fsz, f) != (size_t)fsz) { free(buf); fclose(f); return -1; }
    fclose(f);
    buf[fsz] = '\0';

    long long ver = json_int_val(buf, "version", 1);
    if (ver != 1)
        fprintf(stderr, "z-scp: warning: meta %s has version %lld (expected 1)\n",
                path, ver);

    /* Locate the "files" object */
    const char *files_start = strstr(buf, "\"files\"");
    if (!files_start) { free(buf); return 0; }
    const char *obj = strchr(files_start, '{');
    if (!obj) { free(buf); return 0; }
    obj++; /* skip '{' */

    /*
     * Scan entries of the form:
     *   "rel/path": { "ccsid": N, "tag": "on|off", "mode": "OOOO",
     *                 "mtime": T [, "extattr": "XXXX"]
     *                 [, "useraudit": "..."] [, "auditoraudit": "..."] }
     *
     * We walk character by character, finding the opening '"' of each key,
     * then locate the matching value object '{' ... '}'.
     */
    const char *p = obj;
    while (*p) {
        /* skip whitespace and commas */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') p++;
        if (*p == '}' || *p == '\0') break;   /* end of "files" object */
        if (*p != '"') { p++; continue; }

        /* read the key (rel_path) */
        p++;
        char rel_path[4096] = {0};
        size_t rlen = 0;
        int key_trunc = 0;
        while (*p && *p != '"') {
            if (rlen + 1 >= sizeof(rel_path)) { key_trunc = 1; break; }
            if (*p == '\\' && *(p+1)) p++;
            rel_path[rlen++] = *p++;
        }
        rel_path[rlen] = '\0';
        if (key_trunc) {
            fprintf(stderr, "z-scp: warning: meta key too long, skipping\n");
            while (*p && *p != '"') p++;
        }
        if (*p == '"') p++;

        /* skip to ':' then '{' */
        while (*p && *p != ':') p++;
        if (*p == ':') p++;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p != '{') continue;

        /* find matching '}' — one level deep, string-aware so braces
         * inside quoted values (e.g. paths) don't break the scan. */
        const char *obj_start = p + 1;
        int depth = 1;
        int in_str = 0, esc = 0;
        const char *q = p + 1;
        while (*q && depth > 0) {
            char c = *q;
            if (in_str) {
                if (esc) esc = 0;
                else if (c == '\\') esc = 1;
                else if (c == '"') in_str = 0;
            } else {
                if (c == '"') in_str = 1;
                else if (c == '{') depth++;
                else if (c == '}') depth--;
            }
            q++;
        }
        if (depth > 0) break; /* truncated file */
        /* q now points just past the closing '}' */
        size_t obj_len = (size_t)(q - obj_start - 1);
        char *entry_buf = malloc(obj_len + 1);
        if (!entry_buf) { p = q; continue; }
        memcpy(entry_buf, obj_start, obj_len);
        entry_buf[obj_len] = '\0';

        meta_entry_t *e = meta_db_add(db);
        if (!e) { free(entry_buf); free(buf); return -1; }
        if (snprintf(e->rel_path, sizeof(e->rel_path), "%s", rel_path)
                >= (int)sizeof(e->rel_path)) {
            fprintf(stderr, "z-scp: warning: meta key truncated: %s\n", rel_path);
        }

        long long ccsid_ll = json_int_val(entry_buf, "ccsid",  0);
        e->ccsid = (ccsid_ll == 819 || ccsid_ll == 1047 || ccsid_ll == 65535)
                   ? (int)ccsid_ll : 0;
        e->mtime   = (time_t)json_int_val(entry_buf, "mtime", 0);

        char tmp[64];
        if (json_str_val(entry_buf, "tag",  tmp, sizeof(tmp)))
            e->tag_on = (strcmp(tmp, "on") == 0) ? 1 : 0;
        if (json_str_val(entry_buf, "mode", tmp, sizeof(tmp))) {
            char *end = NULL;
            long mv = strtol(tmp, &end, 8);
            if (end != tmp && mv >= 0 && mv <= 07777)
                e->mode = (mode_t)mv;
        }
        /* copy short fixed-width fields; clamp to buffer without GCC truncation warning */
        if (json_str_val(entry_buf, "extattr", tmp, sizeof(tmp))) {
            size_t n = strlen(tmp); if (n >= sizeof(e->extattr)) n = sizeof(e->extattr)-1;
            memcpy(e->extattr, tmp, n); e->extattr[n] = '\0';
        }
        if (json_str_val(entry_buf, "useraudit", tmp, sizeof(tmp))) {
            size_t n = strlen(tmp); if (n >= sizeof(e->useraudit)) n = sizeof(e->useraudit)-1;
            memcpy(e->useraudit, tmp, n); e->useraudit[n] = '\0';
        }
        if (json_str_val(entry_buf, "auditoraudit", tmp, sizeof(tmp))) {
            size_t n = strlen(tmp); if (n >= sizeof(e->auditoraudit)) n = sizeof(e->auditoraudit)-1;
            memcpy(e->auditoraudit, tmp, n); e->auditoraudit[n] = '\0';
        }

        free(entry_buf);
        p = q;
    }

    free(buf);
    return 0;
}

/*
 * meta_default_path: build the default meta file path.
 * For a directory transfer, it lives inside the local root as .z-scp-meta.json.
 * For a single-file transfer, it lives in the same directory as the local file.
 * Returns 0 ok, -1 if the result does not fit.
 */
static int meta_default_path(char *out, size_t outsz,
                               const char *local, int is_dir) {
    if (is_dir) {
        return snprintf(out, outsz, "%s/.z-scp-meta.json", local)
               < (int)outsz ? 0 : -1;
    } else {
        /* place alongside the file */
        const char *slash = strrchr(local, '/');
        if (slash) {
            size_t dlen = (size_t)(slash - local);
            if (dlen + 18 > outsz) return -1;
            memcpy(out, local, dlen);
            memcpy(out + dlen, "/.z-scp-meta.json", 18);
            return 0;
        } else {
            return snprintf(out, outsz, ".z-scp-meta.json")
                   < (int)outsz ? 0 : -1;
        }
    }
}

/* =========================================================================
 * PAX archive writer
 * ====================================================================== */

/*
 * pax_write: write n bytes to fd, converting each byte with e2a[] for
 * PAX_EBCDIC uploads to z/OS.
 */
static ssize_t pax_write(int fd, const void *buf, size_t n, pax_enc_t enc) {
    if (enc == PAX_ASCII) return write(fd, buf, n);
    unsigned char tmp[8192];
    const unsigned char *src = (const unsigned char *)buf;
    size_t done = 0;
    while (done < n) {
        size_t chunk = n - done < sizeof(tmp) ? n - done : sizeof(tmp);
        for (size_t i = 0; i < chunk; i++) tmp[i] = e2a[src[done + i]];
        ssize_t w = write(fd, tmp, chunk);
        if (w <= 0) return done ? (ssize_t)done : -1;
        done += (size_t)w;
    }
    return (ssize_t)done;
}

/* Write exactly n zero bytes to fd.
 * NOTE: raw write() is correct even for PAX_EBCDIC: e2a[0]==0, and AUTOCVT
 * maps 0x00 back to 0x00, so padding is invariant under the transport. */
static int write_zeros(int fd, size_t n) {
    unsigned char zero[512] = {0};
    while (n > 0) {
        size_t w = n < sizeof(zero) ? n : sizeof(zero);
        if (write(fd, zero, w) != (ssize_t)w) return -1;
        n -= w;
    }
    return 0;
}

/*
 * set_checksum: fill the ustar checksum field.
 *
 * NOTE: the sum is intentionally computed on the *logical* (pre-transport)
 * header bytes.  For PAX_EBCDIC uploads pax_write() translates each byte
 * with e2a[] on the wire, but z/OS SSH AUTOCVT translates stdin back with
 * a2e[] before pax sees it (verified: `echo 111 | ssh host od -x` shows
 * F1 F1 F1 15, i.e. ASCII→EBCDIC in transit), so remote pax validates the
 * checksum against the original bytes.  Checksumming the wire bytes would
 * therefore *break* validation — the transport conversion must not apply
 * to this calculation.
 */
static void set_checksum(unsigned char hdr[512], pax_enc_t enc) {
    (void)enc;
    memset(hdr + 148, ' ', 8);
    unsigned sum = 0;
    for (int i = 0; i < 512; i++) sum += hdr[i];
    snprintf((char *)hdr + 148, 8, "%06o", sum);
    hdr[154] = '\0'; hdr[155] = ' ';
}

/*
 * write_pax_ghdr: write a PAX 'g' global extended header carrying z/OS
 * per-file attributes that pax -r restores natively.
 *
 * Only written when at least one attribute is non-default:
 *   ZOS.extattr != "----"
 *   ZOS.useraudit != "fff"  (default = no auditing)
 *   ZOS.auditoraudit != "---"
 *
 * z/OS pax -r applies 'g' header values to the immediately following file
 * entry, which is exactly what we want (one 'g' per file that needs it).
 */
/* Append one "LEN KEY=VALUE\n" pax record to xdata (size xdatsz, *xlen used).
 * Returns 0 ok, -1 on overflow. */
static int xhdr_append(char *xdata, size_t xdatsz, int *xlen,
                       const char *key, const char *val) {
    char tmp[128];
    int reclen, n = -1;
    for (reclen = 1; reclen <= 99; reclen++) {
        n = snprintf(tmp, sizeof(tmp), "%d %s=%s\n", reclen, key, val);
        if (n == reclen) break;
    }
    if (n != reclen) return -1;
    if (*xlen + n >= (int)xdatsz) return -1;
    memcpy(xdata + *xlen, tmp, (size_t)n);
    *xlen += n;
    return 0;
}

static int write_pax_ghdr(int fd, const meta_entry_t *e, pax_enc_t enc) {
    char xdata[512];
    int  xlen = 0;

    /* extattr */
    if (strcmp(e->extattr, "----") != 0) {
        if (xhdr_append(xdata, sizeof(xdata), &xlen, "ZOS.extattr", e->extattr) != 0)
            return -1;
    }
    /* useraudit */
    if (strcmp(e->useraudit, "fff") != 0) {
        if (xhdr_append(xdata, sizeof(xdata), &xlen, "ZOS.useraudit", e->useraudit) != 0)
            return -1;
    }
    /* auditoraudit */
    if (strcmp(e->auditoraudit, "---") != 0) {
        if (xhdr_append(xdata, sizeof(xdata), &xlen, "ZOS.auditoraudit", e->auditoraudit) != 0)
            return -1;
    }

    if (xlen == 0) return 0;   /* nothing to emit */

    unsigned char hdr[512];
    memset(hdr, 0, 512);
    snprintf((char *)hdr,       100, "GlobalHead.%d.1", (int)getpid());
    snprintf((char *)hdr + 100,   8, "%07o", 0600);
    snprintf((char *)hdr + 108,   8, "%07o", 0);
    snprintf((char *)hdr + 116,   8, "%07o", 0);
    snprintf((char *)hdr + 124,  12, "%011o", xlen);
    snprintf((char *)hdr + 136,  12, "%011llo", (unsigned long long)e->mtime);
    hdr[156] = 'g';
    memcpy(hdr + 257, "ustar\0" "00", 8);
    set_checksum(hdr, enc);
    if (pax_write(fd, hdr, 512, enc) != 512) return -1;
    if (pax_write(fd, xdata, xlen, enc) != xlen) return -1;
    size_t pad = (512 - (xlen % 512)) % 512;
    if (pad && write_zeros(fd, pad) != 0) return -1;
    return 0;
}

/*
 * write_pax_xhdr: write a PAX 'x' per-file extended header with ZOS.taginfo.
 * Also writes ZOS.taginfo=0 (T=off) when tag_on==0 so pax -r sets T=off.
 */
static int write_pax_xhdr(int fd, const char *basename,
                           int ccsid, int tag_on,
                           pax_enc_t enc, mode_t mode, time_t mtime) {
    char xdata[128];
    int  xlen = 0;
    char val[32];
    int flag = tag_on ? 1 : 0;
    int out_ccsid = (ccsid == 65535) ? 65535 : (ccsid ? ccsid : 65535);
    snprintf(val, sizeof(val), "%d %d", flag, out_ccsid);
    if (xhdr_append(xdata, sizeof(xdata), &xlen, "ZOS.taginfo", val) != 0)
        return -1;

    unsigned char hdr[512];
    memset(hdr, 0, 512);
    snprintf((char *)hdr, 100, "PaxHeader/%.88s", basename);
    snprintf((char *)hdr + 100, 8, "%07o", (unsigned)(mode & 07777));
    snprintf((char *)hdr + 108, 8, "%07o", 0);
    snprintf((char *)hdr + 116, 8, "%07o", 0);
    snprintf((char *)hdr + 124, 12, "%011o", xlen);
    snprintf((char *)hdr + 136, 12, "%011llo", (unsigned long long)mtime);
    hdr[156] = 'x';
    memcpy(hdr + 257, "ustar\0" "00", 8);
    set_checksum(hdr, enc);
    if (pax_write(fd, hdr, 512, enc) != 512) return -1;
    if (pax_write(fd, xdata, xlen, enc) != xlen) return -1;
    size_t pad = (512 - (xlen % 512)) % 512;
    if (pad && write_zeros(fd, pad) != 0) return -1;
    return 0;
}

/*
 * write_pax_file: write the ustar file header + content to fd.
 *
 * to_ebcdic controls content encoding:
 *   1 → local file holds ASCII (post-download state or ASCII source);
 *       convert ASCII→EBCDIC via a2e[] so z/OS stores EBCDIC bytes.
 *       Set ONLY from an explicit meta entry (ccsid=1047) or --ccsid.
 *   0 → pass through as-is.  This covers 819/binary AND auto-detected
 *       1047 without meta: in the latter case the local bytes already look
 *       like EBCDIC, so running them through a2e[] again would double-
 *       convert (EBCDIC-as-Latin1 → garbage).  Passthrough stores the
 *       on-disk bytes under the 1047 tag, which is the faithful choice.
 *
 * The file size comes from fstat() on the open fd (not the caller's stat),
 * and at most that many bytes are streamed: a concurrent grower is
 * truncated to the header size so the archive stays in sync; a concurrent
 * shrink is zero-padded and reported as an error.
 */
static int write_pax_file(int fd, const char *path, const char *arcname,
                          int to_ebcdic, pax_enc_t enc,
                          mode_t mode, time_t mtime) {
    int src = open(path, O_RDONLY);
    if (src < 0) { fprintf(stderr, "z-scp: open %s: %s\n", path, strerror(errno)); return -1; }
    struct stat fst;
    if (fstat(src, &fst) != 0) {
        fprintf(stderr, "z-scp: fstat %s: %s\n", path, strerror(errno));
        close(src);
        return -1;
    }
    if (!S_ISREG(fst.st_mode)) {
        fprintf(stderr, "z-scp: not a regular file: %s\n", path);
        close(src);
        return -1;
    }
    off_t filesize = fst.st_size;

    unsigned char hdr[512];
    memset(hdr, 0, 512);

    /* ustar name + prefix (supports paths >100 chars via prefix/name split) */
    {
        size_t alen = strlen(arcname);
        if (alen <= 100) {
            memcpy(hdr, arcname, alen);
        } else {
            size_t split = 0;
            for (size_t i = alen; i > 0; i--) {
                if (arcname[i - 1] == '/') {
                    size_t pre = i - 1, rest = alen - i;
                    if (pre <= 155 && rest <= 100 && rest > 0) { split = i; break; }
                }
                if (alen - i > 100) break; /* name part only grows toward front */
            }
            if (!split) {
                fprintf(stderr, "z-scp: name too long for ustar: %s\n", arcname);
                close(src);
                return -1;
            }
            memcpy(hdr, arcname + split, alen - split);
            memcpy(hdr + 345, arcname, split - 1);
        }
    }
    snprintf((char *)hdr + 100,    8, "%07o", (unsigned)(mode & 07777));
    snprintf((char *)hdr + 108,    8, "%07o", 0);
    snprintf((char *)hdr + 116,    8, "%07o", 0);
    snprintf((char *)hdr + 124,   12, "%011llo", (unsigned long long)filesize);
    snprintf((char *)hdr + 136,   12, "%011llo", (unsigned long long)mtime);
    hdr[156] = '0'; /* regular file */
    memcpy(hdr + 257, "ustar\0" "00", 8);
    set_checksum(hdr, enc);
    if (pax_write(fd, hdr, 512, enc) != 512) { close(src); return -1; }

    unsigned char ibuf[8192];
    unsigned char obuf[8192];
    ssize_t nr;
    off_t remaining = filesize, written = 0;
    int rc = 0;
    while (remaining > 0) {
        size_t want = (remaining < (off_t)sizeof(ibuf)) ? (size_t)remaining : sizeof(ibuf);
        nr = read(src, ibuf, want);
        if (nr < 0 && errno == EINTR) continue;
        if (nr <= 0) break; /* EOF early (shrunk) or error */
        if (to_ebcdic)
            for (ssize_t i = 0; i < nr; i++) obuf[i] = a2e[ibuf[i]];
        else
            memcpy(obuf, ibuf, (size_t)nr);
        if (pax_write(fd, obuf, (size_t)nr, enc) != nr) { rc = -1; break; }
        remaining -= nr;
        written += nr;
    }
    if (rc == 0 && remaining > 0) {
        /* file shrank mid-transfer: pad so the archive stays valid */
        fprintf(stderr, "z-scp: warning: %s shrank during upload, padding\n", path);
        unsigned char zero[8192] = {0};
        while (remaining > 0) {
            size_t chunk = (remaining < (off_t)sizeof(zero)) ? (size_t)remaining : sizeof(zero);
            if (pax_write(fd, zero, chunk, enc) != (ssize_t)chunk) { rc = -1; break; }
            remaining -= chunk;
            written += chunk;
        }
        if (rc == 0) rc = -1; /* signal shortfall even though stream is intact */
    }
    /* Ignore trailing growth beyond the header size: already truncated by
     * construction (we read at most filesize bytes). */
    close(src);

    size_t pad = (512 - ((size_t)(written % 512))) % 512;
    if (pad && write_zeros(fd, pad) != 0) return -1;

    return rc;
}

/* =========================================================================
 * Global flags (set by argument parser, read by transfer functions)
 * ====================================================================== */

static int dry_run      = 0;
static int reprobe      = 0;
static int do_verify    = 0;
static int recursive    = 0;
static int force_ccsid  = 0;
static int smart        = 0;
static int use_meta     = 0;   /* --meta or --meta-file specified */
static char meta_path[4096];   /* resolved meta file path */

/* =========================================================================
 * PAX archive reader (for download)
 * ====================================================================== */

#define PAX_BLOCK 512

/* Read one 512-byte block, undoing the AUTOCVT transport conversion.
 * z/OS SSH applies e2a[] to stdout bytes at the boundary (confirmed with
 * `... | ssh host od -x`: ASCII 0x31 arrives as EBCDIC 0xF1), so a2e[]
 * recovers the original on-disk bytes.  Block-oriented fread, not fgetc.
 * NOTE: transfers unconditionally assume AUTOCVT=ON (remote commands set
 * _BPXK_AUTOCVT=ON explicitly); the host probe is diagnostic only and
 * never switches this codec, so a mis-probe cannot corrupt transfers. */
static int pipe_read_block(FILE *pipe, unsigned char buf[PAX_BLOCK]) {
    size_t got = 0;
    while (got < PAX_BLOCK) {
        size_t n = fread(buf + got, 1, PAX_BLOCK - got, pipe);
        if (n == 0) return -1;
        got += n;
    }
    for (int i = 0; i < PAX_BLOCK; i++) buf[i] = a2e[buf[i]];
    return 0;
}

/* Parse ASCII octal field */
static long long parse_octal(const char *s, int len) {
    long long v = 0;
    for (int i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '7') break;
        v = v * 8 + (s[i] - '0');
    }
    return v;
}

/*
 * xhdr_state_t: accumulates ZOS.* values from 'g' and 'x' headers for one
 * file entry.  Cleared after each regular file ('0') is processed.
 * 'g' values are overridden by 'x' values when both are present.
 */
typedef struct {
    int  ccsid;            /* from ZOS.taginfo in 'x' (0 = absent / T=off) */
    int  tag_on;           /* 1 if ZOS.taginfo=1 seen in 'x' */
    char extattr[5];       /* from ZOS.extattr in 'g' */
    char useraudit[8];     /* from ZOS.useraudit in 'g' */
    char auditoraudit[8];  /* from ZOS.auditoraudit in 'g' */
} xhdr_state_t;

static void xhdr_state_reset(xhdr_state_t *s) {
    s->ccsid = 0; s->tag_on = 0;
    strcpy(s->extattr,      "----");
    strcpy(s->useraudit,    "fff");
    strcpy(s->auditoraudit, "---");
}

/*
 * parse_xhdr_fields: scan all "LENGTH KEY=VALUE\n" records in data[0..len].
 * Recognises ZOS.taginfo, ZOS.extattr, ZOS.useraudit, ZOS.auditoraudit,
 * and IBM.codepage.  Fills the appropriate fields in *s.
 * is_global: if 1, this is a 'g' header (fills extattr/audit but not ccsid).
 *            if 0, this is an 'x' header (fills ccsid/tag_on).
 */
static void parse_xhdr_fields(const char *data, size_t len,
                               xhdr_state_t *s, int is_global) {
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && data[j] != '\n') j++;
        /* find key: skip leading digits and space */
        size_t k = i;
        while (k < j && data[k] != ' ') k++;
        k++;   /* skip space */
        if (k >= j) { i = j + 1; continue; }
        const char *kp = data + k;
        size_t krem = j - k;

        if (!is_global) {
            /* per-file 'x' header */
            if (krem > 12 && strncmp(kp, "ZOS.taginfo=", 12) == 0) {
                const char *v = kp + 12;
                if (*v == '0') {
                    s->tag_on = 0; s->ccsid = 0;
                } else if (*v == '1' && *(v+1) == ' ') {
                    s->tag_on = 1; s->ccsid = atoi(v + 2);
                }
            } else if (krem > 13 && strncmp(kp, "IBM.codepage=", 13) == 0) {
                s->ccsid  = atoi(kp + 13);
                s->tag_on = (s->ccsid != 0 && s->ccsid != 65535) ? 1 : 0;
            }
        } else {
            /* global 'g' header */
            if (krem > 12 && strncmp(kp, "ZOS.extattr=", 12) == 0) {
                size_t vlen = j - (k + 12);
                if (vlen >= 4) {
                    memcpy(s->extattr, kp + 12, 4);
                    s->extattr[4] = '\0';
                }
            } else if (krem > 14 && strncmp(kp, "ZOS.useraudit=", 14) == 0) {
                size_t vlen = j - (k + 14);
                if (vlen > 0 && vlen < sizeof(s->useraudit)) {
                    memcpy(s->useraudit, kp + 14, vlen);
                    s->useraudit[vlen] = '\0';
                }
            } else if (krem > 18 && strncmp(kp, "ZOS.auditoraudit=", 17) == 0) {
                size_t vlen = j - (k + 17);
                if (vlen > 0 && vlen < sizeof(s->auditoraudit)) {
                    memcpy(s->auditoraudit, kp + 17, vlen);
                    s->auditoraudit[vlen] = '\0';
                }
            }
        }
        i = j + 1;
    }
}

/*
 * makedirs: create all components of path (like mkdir -p).
 */
static void makedirs(const char *path) {
    char tmp[4096];
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) {
        fprintf(stderr, "z-scp: path too long, skipping mkdir: %s\n", path);
        return;
    }
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0777);
            *p = '/';
        }
    }
    mkdir(tmp, 0777);
}

/*
 * smart_convert: if --smart is set and ccsid==0, auto-detect and convert.
 */
static void smart_convert(const char *out_path) {
    int is_text = 0;
    int detected = detect_ccsid(out_path, &is_text);
    if (detected != 1047) return;

    FILE *f = fopen(out_path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);
    if (fsz <= 0) { fclose(f); return; }
    if (fsz > (long)SMART_MAX_BYTES) {
        fprintf(stderr, "z-scp: --smart: %s too large (%ld bytes), skipping\n",
                out_path, fsz);
        fclose(f);
        return;
    }
    unsigned char *buf = malloc((size_t)fsz);
    if (!buf) { fclose(f); return; }
    if ((long)fread(buf, 1, (size_t)fsz, f) != fsz) { fclose(f); free(buf); return; }
    fclose(f);
    for (long i = 0; i < fsz; i++) buf[i] = e2a[buf[i]];
    f = fopen(out_path, "wb");
    if (f) { fwrite(buf, 1, (size_t)fsz, f); fclose(f); }
    free(buf);
    fprintf(stderr, "z-scp: smart-converted %s (detected 1047 → 819)\n", out_path);
}

/* Reject archive member names that would escape the destination:
 * absolute paths and any '..' component.  Returns 1 if safe. */
static int rel_is_safe(const char *rel) {
    if (!rel || !*rel) return 0;
    if (rel[0] == '/') return 0;
    const char *p = rel;
    while (*p) {
        const char *slash = strchr(p, '/');
        size_t len = slash ? (size_t)(slash - p) : strlen(p);
        if (len == 2 && p[0] == '.' && p[1] == '.') return 0;
        if (!slash) break;
        p = slash + 1;
    }
    return 1;
}

/* Reconstruct a ustar member name honouring the prefix field (offset 345,
 * 155 bytes) for names longer than 100 chars: "prefix/name". */
static void ustar_name(const unsigned char block[PAX_BLOCK],
                       char *out, size_t outsz) {
    char name[101], prefix[156];
    memcpy(name, block, 100); name[100] = '\0';
    memcpy(prefix, block + 345, 155); prefix[155] = '\0';
    if (prefix[0])
        snprintf(out, outsz, "%s/%s", prefix, name);
    else
        snprintf(out, outsz, "%s", name);
}

/* Apply the archived mode/mtime to a just-written file.  chmod bypasses
 * the umask (open used 0666); utimensat sets atime=mtime=archived mtime. */
static void apply_file_attrs(const char *path, mode_t mode, time_t mtime) {
    if (mode) {
        if (chmod(path, mode & 07777) != 0)
            fprintf(stderr, "z-scp: warning: chmod %s: %s\n",
                    path, strerror(errno));
    }
    if (mtime) {
        struct timespec ts[2];
        ts[0].tv_sec = ts[1].tv_sec = mtime;
        ts[0].tv_nsec = ts[1].tv_nsec = 0;
        if (utimensat(AT_FDCWD, path, ts, 0) != 0)
            fprintf(stderr, "z-scp: warning: utime %s: %s\n",
                    path, strerror(errno));
    }
}

/*
 * pax_extract_entry: read and extract one file entry from the download stream.
 * Returns 0 on success, -1 on error (stream is always fully drained).
 * If meta_db is non-NULL, appends an entry for this file.
 * rel_path: path relative to the download root (used as the meta key).
 * ustar_mode / ustar_mtime: from the file's ustar header.
 */
static int pax_extract_entry(FILE *pipe, const char *out_path,
                              long long sz, const xhdr_state_t *xs,
                              meta_db_t *meta_db, const char *rel_path,
                              mode_t ustar_mode, time_t ustar_mtime) {
    int effective_ccsid = force_ccsid ? force_ccsid : xs->ccsid;

    if (sz < 0) {
        fprintf(stderr, "z-scp: invalid size %lld for %s\n", sz, out_path);
        return -1;
    }

    char parent[4096];
    if (snprintf(parent, sizeof(parent), "%s", out_path) >= (int)sizeof(parent)) {
        fprintf(stderr, "z-scp: path too long: %s\n", out_path);
        long long skip = (sz + PAX_BLOCK - 1) / PAX_BLOCK;
        unsigned char tmp[PAX_BLOCK];
        for (long long b = 0; b < skip; b++) pipe_read_block(pipe, tmp);
        return -1;
    }
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) { *slash = '\0'; makedirs(parent); }

    int out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0) {
        fprintf(stderr, "z-scp: open %s: %s\n", out_path, strerror(errno));
        long long skip = (sz + PAX_BLOCK - 1) / PAX_BLOCK;
        unsigned char tmp[PAX_BLOCK];
        for (long long b = 0; b < skip; b++) pipe_read_block(pipe, tmp);
        return -1;
    }

    long long remaining = sz;
    unsigned char block[PAX_BLOCK];
    while (remaining > 0) {
        if (pipe_read_block(pipe, block) != 0) { close(out); return -1; }
        long long take = remaining < PAX_BLOCK ? remaining : PAX_BLOCK;
        unsigned char outbuf[PAX_BLOCK];
        if (effective_ccsid == 1047) {
            /* z/OS stored EBCDIC; convert to ASCII for local use */
            for (long long i = 0; i < take; i++) outbuf[i] = e2a[block[i]];
        } else {
            memcpy(outbuf, block, take);
        }
        if (write(out, outbuf, take) != (ssize_t)take) {
            fprintf(stderr, "z-scp: write %s: %s\n", out_path, strerror(errno));
            close(out);
            /* drain the rest so the stream stays in sync */
            while (remaining > 0) {
                if (pipe_read_block(pipe, block) != 0) break;
                remaining -= remaining < PAX_BLOCK ? remaining : PAX_BLOCK;
            }
            return -1;
        }
        remaining -= take;
    }
    close(out);
    apply_file_attrs(out_path, ustar_mode, ustar_mtime);

    fprintf(stderr, "z-scp: extracted %s (ccsid=%d tag=%s mode=%04o)\n",
            out_path, effective_ccsid ? effective_ccsid : 65535,
            xs->tag_on ? "on" : "off", (unsigned)(ustar_mode & 07777));

    if (smart && xs->ccsid == 0 && !force_ccsid)
        smart_convert(out_path);

    /* record metadata */
    if (meta_db && rel_path) {
        meta_entry_t *me = meta_db_add(meta_db);
        if (!me) return -1;
        if (snprintf(me->rel_path, sizeof(me->rel_path), "%s", rel_path)
                >= (int)sizeof(me->rel_path))
            fprintf(stderr, "z-scp: warning: rel path truncated: %s\n", rel_path);
        me->ccsid  = effective_ccsid ? effective_ccsid : xs->ccsid;
        me->tag_on = xs->tag_on;
        me->mode   = ustar_mode ? ustar_mode : 0644;
        me->mtime  = ustar_mtime;
        snprintf(me->extattr,      sizeof(me->extattr),      "%s", xs->extattr);
        snprintf(me->useraudit,    sizeof(me->useraudit),    "%s", xs->useraudit);
        snprintf(me->auditoraudit, sizeof(me->auditoraudit), "%s", xs->auditoraudit);
    }

    return 0;
}

/* Strip a remote_root prefix ("u/proj" or "/u/proj") from an archive member
 * path, returning the path relative to the transfer root. */
static const char *strip_root(const char *rel, const char *remote_root) {
    if (remote_root) {
        const char *rr = remote_root;
        while (*rr == '/') rr++;
        size_t rrlen = strlen(rr);
        if (rrlen > 0 && strncmp(rel, rr, rrlen) == 0
                && (rel[rrlen] == '/' || rel[rrlen] == '\0')) {
            rel += rrlen;
            while (*rel == '/') rel++;
        }
    }
    return rel;
}

/*
 * read_pax_stream: read a pax archive stream from z/OS, extracting files.
 *
 * dest_path non-NULL → single-file mode (write first regular file to dest_path).
 * dest_path NULL     → tree mode (strip leading slash, prepend root_dir).
 * remote_root        → used to compute relative paths for meta keys.
 * meta_db            → if non-NULL, populate with per-file attributes.
 */
static int read_pax_stream(FILE *pipe, const char *dest_path,
                           const char *root_dir, const char *remote_root,
                           meta_db_t *meta_db) {
    unsigned char block[PAX_BLOCK];
    xhdr_state_t xs;
    xhdr_state_reset(&xs);
    int nfiles = 0, nerrors = 0;

    while (1) {
        if (pipe_read_block(pipe, block) != 0) break;

        int allzero = 1;
        for (int i = 0; i < PAX_BLOCK; i++) if (block[i]) { allzero = 0; break; }
        if (allzero) break;

        char     type = (char)block[156];
        long long sz  = parse_octal((char *)block + 124, 12);
        mode_t   umode = (mode_t)parse_octal((char *)block + 100, 8);
        time_t   umtime = (time_t)parse_octal((char *)block + 136, 12);
        if (sz < 0) {
            fprintf(stderr, "z-scp: corrupt pax header (negative size), aborting\n");
            return -1;
        }

        if (type == 'g' || type == 'G' || type == 'x' || type == 'X') {
            long long xsz = sz;
            if (xsz > (long long)XHDR_MAX_BYTES) {
                fprintf(stderr, "z-scp: xhdr too large (%lld bytes), aborting\n", xsz);
                return -1;
            }
            char *xdata = malloc(xsz + 1);
            if (!xdata) return -1;
            long long got = 0;
            int xerr = 0;
            while (got < xsz) {
                if (pipe_read_block(pipe, block) != 0) { xerr = 1; break; }
                long long take = (xsz - got < PAX_BLOCK) ? (xsz - got) : PAX_BLOCK;
                memcpy(xdata + got, block, (size_t)take);
                got += take;
            }
            if (xerr) { free(xdata); return -1; }
            xdata[xsz] = '\0';
            int is_global = (type == 'g' || type == 'G');
            parse_xhdr_fields(xdata, (size_t)xsz, &xs, is_global);
            free(xdata);
            continue;
        }

        if (type == '0' || type == '\0') {
            char out_path[4096];
            char rel_path[4096] = {0};

            if (dest_path) {
                if (snprintf(out_path, sizeof(out_path), "%s", dest_path)
                        >= (int)sizeof(out_path)) {
                    fprintf(stderr, "z-scp: path too long: %s\n", dest_path);
                    return -1;
                }
                /* rel_path for single-file: just the basename */
                const char *bn = strrchr(dest_path, '/');
                snprintf(rel_path, sizeof(rel_path), "%s", bn ? bn + 1 : dest_path);
            } else {
                char fullname[512];
                ustar_name(block, fullname, sizeof(fullname));
                const char *rel = fullname;
                while (*rel == '/') rel++;
                /* strip remote_root prefix to get the relative path */
                rel = strip_root(rel, remote_root);
                if (!rel_is_safe(rel)) {
                    fprintf(stderr, "z-scp: refusing unsafe member '%s'\n", fullname);
                    long long skip = (sz + PAX_BLOCK - 1) / PAX_BLOCK;
                    for (long long b = 0; b < skip; b++)
                        if (pipe_read_block(pipe, block) != 0) return -1;
                    xhdr_state_reset(&xs);
                    nerrors++;
                    continue;
                }
                if (snprintf(rel_path, sizeof(rel_path), "%s", rel)
                        >= (int)sizeof(rel_path)
                        || snprintf(out_path, sizeof(out_path), "%s/%s", root_dir, rel)
                        >= (int)sizeof(out_path)) {
                    fprintf(stderr, "z-scp: path too long, skipping '%s'\n", rel);
                    long long skip = (sz + PAX_BLOCK - 1) / PAX_BLOCK;
                    for (long long b = 0; b < skip; b++)
                        if (pipe_read_block(pipe, block) != 0) return -1;
                    xhdr_state_reset(&xs);
                    nerrors++;
                    continue;
                }
            }

            int rc = pax_extract_entry(pipe, out_path, sz, &xs,
                                  meta_db, rel_path[0] ? rel_path : NULL,
                                  umode, umtime);
            if (rc == 0)
                nfiles++;
            else {
                nerrors++;
                if (dest_path) return -1;
            }

            xhdr_state_reset(&xs);
            if (dest_path) return rc;
            continue;
        }

        if (type == '5') {
            if (!dest_path) {
                char fullname[512];
                ustar_name(block, fullname, sizeof(fullname));
                const char *rel = fullname;
                while (*rel == '/') rel++;
                rel = strip_root(rel, remote_root);
                if (*rel == '\0') {
                    /* the transfer root itself — just ensure it exists */
                    makedirs(root_dir);
                } else if (!rel_is_safe(rel)) {
                    fprintf(stderr, "z-scp: refusing unsafe dir '%s'\n", fullname);
                } else {
                    char dir_path[4096];
                    if (snprintf(dir_path, sizeof(dir_path), "%s/%s", root_dir, rel)
                            >= (int)sizeof(dir_path)) {
                        fprintf(stderr, "z-scp: dir path too long: '%s'\n", rel);
                    } else {
                        makedirs(dir_path);
                        if (umode) chmod(dir_path, umode & 07777);
                    }
                }
            }
            xhdr_state_reset(&xs);
            continue;
        }

        /* Skip other entry types */
        if (sz < 0) return -1;
        long long nblocks = (sz + PAX_BLOCK - 1) / PAX_BLOCK;
        for (long long b = 0; b < nblocks; b++)
            if (pipe_read_block(pipe, block) != 0) return nfiles > 0 ? 0 : -1;
        xhdr_state_reset(&xs);
    }

    if (nfiles == 0) {
        if (dest_path)
            fprintf(stderr, "z-scp: no regular file found in pax stream\n");
        return -1;
    }
    if (nerrors) {
        fprintf(stderr, "z-scp: %d file(s) failed\n", nerrors);
        return -1;
    }
    return 0;
}

/* =========================================================================
 * Argument parsing and SSH dispatch
 * ====================================================================== */

/* Split user@host:/path.  Like scp, a bare colon is not enough: the part
 * before the first ':' must not contain '/' (so local files such as
 * /tmp/a:b or ./log:2024 are never mistaken for remote specs). */
static int split_remote(const char *arg, char *host, size_t hostsz,
                        char *path, size_t pathsz) {
    const char *colon = strchr(arg, ':');
    if (!colon) return 0;
    size_t hlen = (size_t)(colon - arg);
    if (hlen == 0 || hlen >= hostsz) return 0;
    for (size_t i = 0; i < hlen; i++)
        if (arg[i] == '/') return 0;
    memcpy(host, arg, hlen); host[hlen] = '\0';
    if (snprintf(path, pathsz, "%s", colon + 1) >= (int)pathsz) return 0;
    if (!path[0]) return 0;
    return 1;
}

static const char *basename_of(const char *path) {
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

/* =========================================================================
 * Upload helpers
 * ====================================================================== */

typedef struct { char **paths; size_t n, cap; } strlist_t;
/* Queue a (local, remote, rel) triple atomically: either all three are
 * queued (ownership transferred) or none are.  Returns 0 ok, -1 on OOM. */
static int sl_add3(strlist_t *l, char *a, char *b, char *c) {
    if (l->n + 3 > l->cap) {
        size_t ncap = l->cap ? l->cap * 2 : 64;
        while (ncap < l->n + 3) ncap *= 2;
        char **nn = realloc(l->paths, ncap * sizeof(*l->paths));
        if (!nn) return -1;
        l->paths = nn;
        l->cap = ncap;
    }
    l->paths[l->n++] = a;
    l->paths[l->n++] = b;
    l->paths[l->n++] = c;
    return 0;
}

/*
 * upload_one_file: emit optional 'g' header, 'x' header, and file data
 * for a single file into the pax stream on fd.
 *
 * If meta_db is non-NULL and has an entry for rel_path, use it.
 * Otherwise fall back to auto-detect.
 */
static int upload_one_file(int fd, const char *local_path,
                           const char *remote_path, const char *rel_path,
                           const struct stat *st, meta_db_t *meta_db) {
    int ccsid, tag_on, to_ebcdic;
    mode_t  mode  = st->st_mode & 07777;
    time_t  mtime = st->st_mtime;
    const meta_entry_t *me = meta_db ? meta_db_find(meta_db, rel_path) : NULL;

    if (me) {
        /* Meta wins outright (writer always stores mode+mtime, so apply
         * even when they are 0 — 0000/epoch are representable states). */
        ccsid  = me->ccsid;
        tag_on = me->tag_on;
        mode   = me->mode & 07777;
        mtime  = me->mtime;
        /* Local holds ASCII after our download conversion; a meta 1047
         * means "convert back to EBCDIC for storage". */
        to_ebcdic = (me->ccsid == 1047);
    } else {
        /* auto-detect */
        int is_text = 0;
        ccsid = detect_ccsid(local_path, &is_text);
        if (ccsid < 0) return -1;
        tag_on = (ccsid != 65535) ? 1 : 0;
        /* normalise: always tag as 819 unless content scores EBCDIC */
        if (ccsid == 1047) {
            /* Local bytes already look like EBCDIC and there is no meta
             * proving they are post-conversion ASCII: pass through as-is
             * under the 1047 tag (no double conversion). */
            to_ebcdic = 0;
        } else {
            if (ccsid != 65535) ccsid = 819;
            to_ebcdic = 0;
        }
    }

    const char *basename = basename_of(remote_path);

    fprintf(stderr, "z-scp: %s → %s (ccsid=%d tag=%s%s)\n",
            local_path, remote_path, ccsid, tag_on ? "on" : "off",
            me ? "" : " auto-detect");

    if (dry_run) return 0;

    /* emit 'g' header for extattr / audit if needed */
    if (me && (strcmp(me->extattr, "----") != 0
               || strcmp(me->useraudit, "fff") != 0
               || strcmp(me->auditoraudit, "---") != 0)) {
        if (write_pax_ghdr(fd, me, PAX_EBCDIC) != 0) return -1;
    }

    /* determine the ccsid for the ZOS.taginfo xhdr:
     * for tag_on=0 (T=off) we emit ZOS.taginfo=0 with the original ccsid */
    int xhdr_ccsid = ccsid ? ccsid : 65535;

    if (write_pax_xhdr(fd, basename, xhdr_ccsid, tag_on,
                       PAX_EBCDIC, mode, mtime) != 0 ||
        write_pax_file(fd, local_path, remote_path, to_ebcdic,
                       PAX_EBCDIC, mode, mtime) != 0)
        return -1;

    return 0;
}

/*
 * write_pax_tree: walk local_dir recursively, writing a pax archive to fd.
 * rel_prefix is the path of local_dir relative to the upload root (used for
 * meta lookups).
 */
static int write_pax_tree(int fd, const char *local_dir,
                          const char *remote_dir, const char *rel_prefix,
                          meta_db_t *meta_db) {
    DIR *d = opendir(local_dir);
    if (!d) {
        fprintf(stderr, "z-scp: opendir %s: %s\n", local_dir, strerror(errno));
        return 1;
    }

    strlist_t subdirs; subdirs.paths = NULL; subdirs.n = subdirs.cap = 0;
    struct dirent *ent;
    int errors = 0;

    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        /* skip the meta file itself — don't upload it to z/OS.
         * Only at the top level (rel_prefix==""): deeper files that merely
         * share the basename are real payload. */
        if (use_meta && meta_path[0] && rel_prefix[0] == '\0') {
            const char *mb = basename_of(meta_path);
            if (strcmp(ent->d_name, mb) == 0) continue;
        }

        char local_path[4096], remote_path[4096], rel_path[4096];
        if (snprintf(local_path,  sizeof(local_path),  "%s/%s", local_dir,  ent->d_name)
                >= (int)sizeof(local_path)
                || snprintf(remote_path, sizeof(remote_path), "%s/%s", remote_dir, ent->d_name)
                >= (int)sizeof(remote_path)) {
            fprintf(stderr, "z-scp: path too long, skipping %s/%s\n", local_dir, ent->d_name);
            errors++;
            continue;
        }
        if (rel_prefix[0]) {
            if (snprintf(rel_path, sizeof(rel_path), "%s/%s", rel_prefix, ent->d_name)
                    >= (int)sizeof(rel_path)) {
                fprintf(stderr, "z-scp: rel path too long, skipping %s\n", ent->d_name);
                errors++;
                continue;
            }
        } else {
            if (snprintf(rel_path, sizeof(rel_path), "%s", ent->d_name)
                    >= (int)sizeof(rel_path)) {
                fprintf(stderr, "z-scp: rel path too long, skipping %s\n", ent->d_name);
                errors++;
                continue;
            }
        }

        struct stat st;
        if (lstat(local_path, &st) != 0) {
            fprintf(stderr, "z-scp: lstat %s: %s\n", local_path, strerror(errno));
            errors++;
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            char *a = strdup(local_path), *b = strdup(remote_path), *c = strdup(rel_path);
            if (!a || !b || !c) {
                fprintf(stderr, "z-scp: out of memory\n");
                free(a); free(b); free(c);
                errors++;
                continue;
            }
            if (sl_add3(&subdirs, a, b, c) != 0) {
                fprintf(stderr, "z-scp: out of memory\n");
                free(a); free(b); free(c);
                errors++;
                continue;
            }
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            fprintf(stderr, "z-scp: skipping non-regular file %s\n", local_path);
            continue;
        }

        if (upload_one_file(fd, local_path, remote_path, rel_path,
                            &st, meta_db) != 0)
            errors++;
    }
    closedir(d);

    for (size_t i = 0; i + 2 < subdirs.n; i += 3) {
        errors += write_pax_tree(fd, subdirs.paths[i], subdirs.paths[i+1],
                                 subdirs.paths[i+2], meta_db);
        free(subdirs.paths[i]);
        free(subdirs.paths[i+1]);
        free(subdirs.paths[i+2]);
    }
    free(subdirs.paths);
    return errors;
}

static int upload_dir(const char *local_dir, const char *remote_host,
                      const char *remote_dir, meta_db_t *meta_db) {
    if (dry_run) {
        int e = write_pax_tree(-1, local_dir, remote_dir, "", meta_db);
        return e ? 1 : 0;
    }

    /* No user input in this remote command; AUTOCVT is requested
     * explicitly so the transfer never depends on the server default. */
    static const char remote_cmd[] =
        "_BPXK_AUTOCVT=ON /bin/pax -r -x pax -p p";

    fprintf(stderr, "z-scp: streaming pax archive to %s:%s...\n",
            remote_host, remote_dir);

    pid_t pid = -1;
    FILE *pipe = ssh_spawn(remote_host, remote_cmd, 'w', &pid);
    if (!pipe) {
        fprintf(stderr, "z-scp: ssh spawn failed\n");
        return 1;
    }

    int fd = fileno(pipe);
    int errors = write_pax_tree(fd, local_dir, remote_dir, "", meta_db);

    /* End-of-archive: two zero blocks (invariant under AUTOCVT). */
    unsigned char eoa[1024] = {0};
    if (write(fd, eoa, sizeof(eoa)) != sizeof(eoa)) errors++;

    int status = ssh_wait(pipe, pid);
    if (status != 0) {
        if (WIFEXITED(status))
            fprintf(stderr, "z-scp: pax -r failed (exit %d)\n", WEXITSTATUS(status));
        else
            fprintf(stderr, "z-scp: pax -r failed (status %d)\n", status);
        errors++;
    }

    if (!errors) fprintf(stderr, "z-scp: recursive upload complete\n");
    return errors ? 1 : 0;
}

/* Build "_BPXK_AUTOCVT=ON /bin/pax -w -x pax '<path>'" with the path
 * safely quoted for the remote shell.  Returns 0 ok, -1 on truncation. */
static int build_pax_read_cmd(char *out, size_t outsz, const char *remote_path) {
    const char prefix[] = "_BPXK_AUTOCVT=ON /bin/pax -w -x pax ";
    size_t off = 0;
    if (strlen(prefix) + 1 >= outsz) return -1;
    memcpy(out, prefix, sizeof(prefix)); /* includes NUL */
    off = sizeof(prefix) - 1;
    return ssh_quote_append(out, outsz, &off, remote_path);
}

/* =========================================================================
 * Recursive download
 * ====================================================================== */

static int download_dir(const char *remote_host, const char *remote_dir,
                        const char *local_dir, meta_db_t *meta_db) {
    if (dry_run) {
        fprintf(stderr, "z-scp: dry-run: would download %s:%s → %s\n",
                remote_host, remote_dir, local_dir);
        return 0;
    }

    char remote_cmd[4096];
    if (build_pax_read_cmd(remote_cmd, sizeof(remote_cmd), remote_dir) != 0) {
        fprintf(stderr, "z-scp: remote path too long\n");
        return 1;
    }

    fprintf(stderr, "z-scp: streaming pax from %s:%s...\n", remote_host, remote_dir);
    pid_t pid = -1;
    FILE *pipe = ssh_spawn(remote_host, remote_cmd, 'r', &pid);
    if (!pipe) {
        fprintf(stderr, "z-scp: ssh spawn failed\n");
        return 1;
    }

    makedirs(local_dir);
    int rc = read_pax_stream(pipe, NULL, local_dir, remote_dir, meta_db);
    int status = ssh_wait(pipe, pid);
    if (status != 0) {
        if (WIFEXITED(status))
            fprintf(stderr, "z-scp: remote pax -w failed (exit %d)\n",
                    WEXITSTATUS(status));
        else
            fprintf(stderr, "z-scp: remote pax -w failed (status %d)\n", status);
        rc = 1;
    }

    if (!rc) fprintf(stderr, "z-scp: recursive download complete\n");
    return rc ? 1 : 0;
}

/* =========================================================================
 * Single-file upload / download  (pax-based)
 * ====================================================================== */

static int do_upload(const char *local, const char *remote_host,
                     const char *remote_path, meta_db_t *meta_db) {
    struct stat st;
    if (stat(local, &st) != 0) {
        fprintf(stderr, "z-scp: stat %s: %s\n", local, strerror(errno));
        return 1;
    }

    /* rel_path for a single file: the local basename.  This matches the
     * download side (which keys on the local basename too), so a
     * download-then-upload round-trip finds its meta entry even when the
     * remote and local basenames differ. */
    const char *rel_path = basename_of(local);

    fprintf(stderr, "z-scp: upload %s → %s:%s\n", local, remote_host, remote_path);

    if (dry_run) {
        /* Reuse the classifier so dry-run shows the ccsid/tag decision
         * (fd is unused: upload_one_file returns before writing). */
        upload_one_file(-1, local, remote_path, rel_path, &st, meta_db);
        return 0;
    }

    static const char remote_cmd[] =
        "_BPXK_AUTOCVT=ON /bin/pax -r -x pax -p p";

    pid_t pid = -1;
    FILE *pipe = ssh_spawn(remote_host, remote_cmd, 'w', &pid);
    if (!pipe) {
        fprintf(stderr, "z-scp: ssh spawn failed\n");
        return 1;
    }

    int fd = fileno(pipe);
    int rc = 0;
    if (upload_one_file(fd, local, remote_path, rel_path, &st, meta_db) != 0)
        rc = 1;

    /* End-of-archive: two zero blocks (invariant under AUTOCVT). */
    unsigned char eoa[1024] = {0};
    if (write(fd, eoa, sizeof(eoa)) != sizeof(eoa)) rc = 1;

    int status = ssh_wait(pipe, pid);
    if (status != 0) {
        if (WIFEXITED(status))
            fprintf(stderr, "z-scp: pax -r failed (exit %d)\n", WEXITSTATUS(status));
        else
            fprintf(stderr, "z-scp: pax -r failed (status %d)\n", status);
        rc = 1;
    }

    if (!rc) fprintf(stderr, "z-scp: upload complete\n");

    if (!rc && do_verify) {
        char od_cmd[4096];
        const char od_prefix[] = "_BPXK_AUTOCVT=ON /bin/od -An -tx1 -N32 ";
        size_t off = 0;
        if (strlen(od_prefix) + 1 < sizeof(od_cmd)) {
            memcpy(od_cmd, od_prefix, sizeof(od_prefix));
            off = sizeof(od_prefix) - 1;
        }
        if (ssh_quote_append(od_cmd, sizeof(od_cmd), &off, remote_path) != 0) {
            fprintf(stderr, "z-scp: verify path too long, skipping\n");
        } else {
            fprintf(stderr, "z-scp: verify — remote first 32 bytes (hex):\n");
            int vst = ssh_run_discard(remote_host, od_cmd);
            if (vst != 0)
                fprintf(stderr, "z-scp: verify od failed (status %d)\n", vst);
        }
    }

    return rc;
}

static int do_download(const char *remote_host, const char *remote_path,
                       const char *local, meta_db_t *meta_db) {
    fprintf(stderr, "z-scp: download %s:%s → %s\n",
            remote_host, remote_path, local);

    if (dry_run) {
        fprintf(stderr, "z-scp: dry-run: would download %s:%s\n",
                remote_host, remote_path);
        return 0;
    }

    char remote_cmd[4096];
    if (build_pax_read_cmd(remote_cmd, sizeof(remote_cmd), remote_path) != 0) {
        fprintf(stderr, "z-scp: remote path too long\n");
        return 1;
    }

    pid_t pid = -1;
    FILE *pipe = ssh_spawn(remote_host, remote_cmd, 'r', &pid);
    if (!pipe) {
        fprintf(stderr, "z-scp: ssh spawn failed\n");
        return 1;
    }

    int rc = read_pax_stream(pipe, local, NULL, NULL, meta_db);
    int status = ssh_wait(pipe, pid);
    if (status != 0) {
        if (WIFEXITED(status))
            fprintf(stderr, "z-scp: remote pax -w failed (exit %d)\n",
                    WEXITSTATUS(status));
        else
            fprintf(stderr, "z-scp: remote pax -w failed (status %d)\n", status);
        rc = 1;
    }

    if (!rc) fprintf(stderr, "z-scp: download complete\n");
    return rc ? 1 : 0;
}

/* =========================================================================
 * main
 * ====================================================================== */

int main(int argc, char **argv) {
    int meta_path_explicit = 0;   /* 1 if --meta-file was used */
    const char *pos[2] = {0, 0};
    int npos = 0;

    /* Never die with SIGPIPE when the remote pax exits early; writes then
     * fail with EPIPE and surface as ordinary transfer errors. */
    signal(SIGPIPE, SIG_IGN);

    /* Options may appear before, between, or after the two paths
     * (README shows trailing --meta).  Unknown flags are an error. */
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--") == 0) {
            for (int j = i + 1; j < argc; j++) {
                if (npos >= 2) {
                    fprintf(stderr, "z-scp: too many arguments\n");
                    return 1;
                }
                pos[npos++] = argv[j];
            }
            break;
        } else if (strcmp(a, "-r") == 0) recursive = 1;
        else if (strcmp(a, "--dry-run")   == 0) dry_run   = 1;
        else if (strcmp(a, "--reprobe")   == 0) reprobe   = 1;
        else if (strcmp(a, "--verify")    == 0) do_verify = 1;
        else if (strcmp(a, "--smart")     == 0) smart     = 1;
        else if (strcmp(a, "--meta")      == 0) use_meta  = 1;
        else if (strcmp(a, "--ccsid")     == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "z-scp: --ccsid requires a value\n"); return 1; }
            char *end = NULL;
            errno = 0;
            long cv = strtol(argv[++i], &end, 10);
            if (errno != 0 || end == argv[i] || *end != '\0' || cv <= 0 || cv > 65535) {
                fprintf(stderr, "z-scp: invalid --ccsid '%s' (want 1..65535)\n", argv[i]);
                return 1;
            }
            force_ccsid = (int)cv;
        }
        else if (strcmp(a, "--meta-file") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "z-scp: --meta-file requires a filename\n"); return 1; }
            use_meta = 1;
            meta_path_explicit = 1;
            if (snprintf(meta_path, sizeof(meta_path), "%s", argv[++i])
                    >= (int)sizeof(meta_path)) {
                fprintf(stderr, "z-scp: --meta-file path too long\n");
                return 1;
            }
        }
        else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "z-scp: unknown option '%s'\n", a);
            return 1;
        }
        else {
            if (npos >= 2) {
                fprintf(stderr, "z-scp: too many arguments\n");
                return 1;
            }
            pos[npos++] = a;
        }
    }

    if (npos != 2) {
        fprintf(stderr,
                "Usage: z-scp [options] <source> <destination>\n"
                "  upload:   z-scp localfile       user@host:/remote/path\n"
                "  download: z-scp user@host:/remote/path  localfile\n"
                "Options:\n"
                "  -r              recursive directory transfer\n"
                "  --dry-run       show what would be done without transferring\n"
                "  --verify        after upload, dump first 32 remote bytes via /bin/od\n"
                "  --ccsid N       force CCSID N for download conversion\n"
                "  --smart         auto-detect encoding for untagged downloads\n"
                "  --meta          read/write .z-scp-meta.json alongside local files\n"
                "  --meta-file F   read/write meta data to/from file F\n"
                "  --reprobe       refresh cached PAX-header probe for the host\n");
        return 1;
    }

    const char *src = pos[0];
    const char *dst = pos[1];

    char src_host[256], src_path[1024];
    char dst_host[256], dst_path[1024];

    int src_remote = split_remote(src, src_host, sizeof(src_host),
                                       src_path, sizeof(src_path));
    int dst_remote = split_remote(dst, dst_host, sizeof(dst_host),
                                       dst_path, sizeof(dst_path));

    if (src_remote && dst_remote) {
        fprintf(stderr, "z-scp: remote-to-remote not supported\n");
        return 1;
    }
    if (!src_remote && !dst_remote) {
        fprintf(stderr, "z-scp: at least one side must be remote (user@host:/path)\n");
        return 1;
    }

    int is_upload = !src_remote;
    /* local side is dst for download, src for upload */
    const char *local_side = is_upload ? src : dst;
    const char *remote_host = is_upload ? dst_host : src_host;

    /* Resolve (and cache) the host's pax-header encoding.  Diagnostic only:
     * transfers pin PAX_EBCDIC with explicit _BPXK_AUTOCVT=ON, so a
     * mis-probe can never corrupt data (see pipe_read_block). */
    if (!dry_run) {
        g_pax_enc = get_host_enc(remote_host, reprobe);
        if (g_pax_enc != PAX_EBCDIC)
            fprintf(stderr, "z-scp: warning: %s probed as ASCII pax headers; "
                    "transfers still assume EBCDIC with AUTOCVT=ON\n",
                    remote_host);
    }

    /* resolve meta path if --meta (bare) was given */
    if (use_meta && !meta_path_explicit) {
        int is_dir = 0;
        struct stat st;
        if (!is_upload && recursive) is_dir = 1;
        if ( is_upload && stat(local_side, &st) == 0 && S_ISDIR(st.st_mode)) is_dir = 1;
        if (meta_default_path(meta_path, sizeof(meta_path), local_side, is_dir) != 0) {
            fprintf(stderr, "z-scp: local path too long for meta default\n");
            return 1;
        }
    }

    /* load meta db for upload; allocate empty db for download */
    meta_db_t meta_db;
    meta_db_init(&meta_db);

    if (use_meta && is_upload) {
        if (meta_read(meta_path, &meta_db) == 0)
            fprintf(stderr, "z-scp: loaded meta from %s (%zu entries)\n",
                    meta_path, meta_db.n);
        else
            fprintf(stderr, "z-scp: no meta file at %s — using auto-detect\n",
                    meta_path);
    }

    int rc = 0;

    if (is_upload) {
        if (recursive) {
            struct stat st;
            if (stat(src, &st) == 0 && S_ISDIR(st.st_mode))
                rc = upload_dir(src, dst_host, dst_path,
                                use_meta ? &meta_db : NULL);
            else
                rc = do_upload(src, dst_host, dst_path,
                               use_meta ? &meta_db : NULL);
        } else {
            rc = do_upload(src, dst_host, dst_path,
                           use_meta ? &meta_db : NULL);
        }
    } else {
        if (recursive)
            rc = download_dir(src_host, src_path, dst,
                              use_meta ? &meta_db : NULL);
        else
            rc = do_download(src_host, src_path, dst,
                             use_meta ? &meta_db : NULL);

        /* write meta file after download */
        if (!rc && use_meta && meta_db.n > 0) {
            const char *host      = src_host;
            const char *rem_root  = src_path;
            const char *loc_root  = dst;
            if (meta_write(meta_path, &meta_db, host, rem_root, loc_root) == 0)
                fprintf(stderr, "z-scp: wrote meta to %s (%zu entries)\n",
                        meta_path, meta_db.n);
        }
    }

    meta_db_free(&meta_db);
    return rc;
}

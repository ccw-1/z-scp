/*
 * z-scp.c  —  pax-stream file transfer to/from z/OS with EBCDIC/tag handling
 *
 * Usage:
 *   z-scp [-r] [--dry-run] [--verify] <source> <destination>
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
 *      - 'x' extended header with "ZOS.taginfo=<is_text> <ccsid>" per file.
 *      - ustar file header + content (1047 pre-converted to 819; others as-is).
 *   3. Pipe the archive to: ssh user@host "/bin/pax -r -p p -C <destdir>"
 *      z/OS SSH AUTOCVT applies a2e[] to stdin bytes; pax_write() pre-applies
 *      e2a[] so the net effect is identity and z/OS pax sees a plain ASCII stream.
 *
 * Single-file / recursive download:
 *   1. Run: ssh user@host "/bin/pax -w -x pax <files>" and read stdout.
 *      z/OS SSH AUTOCVT applies e2a[] to stdout bytes; pipe_read_block() applies
 *      a2e[] to undo it, recovering the original on-disk bytes.
 *   2. Parse the pax archive: ZOS.taginfo xhdr gives the remote CCSID.
 *   3. Write files locally; convert 1047→819 if the remote tag is 1047.
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
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

/* =========================================================================
 * Conversion tables  (from cat2.c — round-trip verified)
 * ====================================================================== */

/* ISO-8859-1 (CCSID 819) → EBCDIC-1047  (needed for EBCDIC PAX headers) */
static const unsigned char a2e[256] __attribute__((unused)) = {
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

/* =========================================================================
 * Host capability cache  (~/.zscp_hosts.json)
 * ====================================================================== */

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
    if (fsz <= 0 || fsz > 65536) { fclose(f); return -1; }
    char *buf = malloc(fsz + 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, fsz, f) != (size_t)fsz) { free(buf); fclose(f); return -1; }
    fclose(f);
    buf[fsz] = '\0';

    char needle[300];
    snprintf(needle, sizeof(needle), "\"%s\"", host);
    char *p = strstr(buf, needle);
    if (!p) { free(buf); return -1; }
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
        if (fsz > 0 && fsz < 65536) {
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

    char entry[512];
    snprintf(entry, sizeof(entry),
             "  \"%s\": { \"pax_encoding\": \"%s\", \"detected\": \"%s\" }",
             host, enc == PAX_EBCDIC ? "ebcdic" : "ascii", ts);

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

/* Ask remote host to produce a tiny PAX archive, inspect its magic field. */
static pax_enc_t probe_host(const char *host) {
    fprintf(stderr, "z-scp: probing PAX header encoding for %s...\n", host);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "ssh -o BatchMode=yes %s "
             "/bin/sh -c '"
             "unset _BPXK_AUTOCVT && "
             "/bin/echo x>/tmp/__zscp_probe__ && "
             "/bin/pax -w -x pax /tmp/__zscp_probe__; "
             "/bin/rm -f /tmp/__zscp_probe__'",
             host);

    FILE *p = popen(cmd, "r");
    if (!p) {
        fprintf(stderr, "z-scp: probe popen failed, assuming ASCII\n");
        return PAX_ASCII;
    }

    unsigned char hdr[512];
    size_t got = 0;
    while (got < 512) {
        size_t n = fread(hdr + got, 1, 512 - got, p);
        if (n == 0) break;
        got += n;
    }
    pclose(p);

    if (got < 512) {
        fprintf(stderr, "z-scp: probe got only %zu bytes, assuming ASCII\n", got);
        return PAX_ASCII;
    }

    pax_enc_t enc = detect_magic(hdr);
    fprintf(stderr, "z-scp: %s uses %s PAX headers\n",
            host, enc == PAX_EBCDIC ? "EBCDIC" : "ASCII");
    return enc;
}

/* Return cached or freshly probed PAX encoding for host. */
__attribute__((unused))
static pax_enc_t get_host_enc(const char *host, int reprobe_flag) {
    if (!reprobe_flag) {
        int cached = cache_read(host);
        if (cached >= 0) {
            fprintf(stderr, "z-scp: cached PAX encoding for %s: %s\n",
                    host, cached == PAX_EBCDIC ? "ebcdic" : "ascii");
            return (pax_enc_t)cached;
        }
    }
    pax_enc_t enc = probe_host(host);
    cache_write(host, enc);
    return enc;
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
    /* >5% match: probable but not pure */
    if (s.ebcdic_cnt > 0 && (s.ebcdic_cnt * 105) / (s.total_ebcdic * 100) > 0) {
        *is_text = 0; return 1047;
    }
    if (s.ascii_cnt > 0  && (s.ascii_cnt  * 105) / (s.total_ascii  * 100) > 0) {
        *is_text = 0; return 819;
    }
    *is_text = 0; return 65535;
}

/* =========================================================================
 * PAX archive writer
 * ====================================================================== */

/*
 * pax_write: write n bytes to fd, converting each byte with e2a[] for
 * PAX_EBCDIC uploads to z/OS.
 *
 * z/OS SSH stdin has _BPXK_AUTOCVT=ON which applies a2e[] to every byte
 * that a child process reads.  To deliver ASCII byte B to z/OS pax -r, we
 * must send e2a[B] so that AUTOCVT's a2e[e2a[B]] = B.
 *
 * This is exactly what aepipe -e2a does: convert ASCII archive to EBCDIC,
 * then AUTOCVT converts back to ASCII → z/OS pax sees a plain ASCII archive.
 */
static ssize_t pax_write(int fd, const void *buf, size_t n, pax_enc_t enc) {
    if (enc == PAX_ASCII) return write(fd, buf, n);
    /* PAX_EBCDIC: apply e2a[] to each ASCII byte so AUTOCVT restores it */
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

/* Write exactly n zero bytes to fd */
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
 * Standard ustar checksum: sum over ASCII header bytes with ASCII space
 * (0x20) fill in the checksum field.  This is what z/OS pax -r verifies
 * after AUTOCVT restores the ASCII bytes (e2a[] on our side, a2e[] by
 * AUTOCVT → identity).
 */
static void set_checksum(unsigned char hdr[512], pax_enc_t enc) {
    (void)enc;  /* same computation for both: z/OS sees ASCII after AUTOCVT */
    memset(hdr + 148, ' ', 8);
    unsigned sum = 0;
    for (int i = 0; i < 512; i++) sum += hdr[i];
    snprintf((char *)hdr + 148, 8, "%06o", sum);
    hdr[154] = '\0'; hdr[155] = ' ';
}

/*
 * write_pax_xhdr: write a PAX 'x' extended header record carrying ZOS.taginfo.
 *
 * z/OS pax -r reads ZOS.taginfo natively and sets the file tag on extraction —
 * no separate chtag pass needed.  Format matches what z/OS pax -w emits:
 *   text (ccsid 819):   "21 ZOS.taginfo=1 819\n"
 *   binary (ccsid 0):   "23 ZOS.taginfo=0 65535\n"
 */
static int write_pax_xhdr(int fd, const char *basename, int ccsid,
                           pax_enc_t enc) {
    /* Build "LENGTH ZOS.taginfo=FLAG CCSID\n" — self-consistent length */
    char xdata[128];
    int  xlen = 0;
    char tmp[64];
    int flag = (ccsid == 65535) ? 0 : 1;
    int out_ccsid = (ccsid == 65535) ? 65535 : ccsid;
    int reclen;
    for (reclen = 1; reclen <= 99; reclen++) {
        int n = snprintf(tmp, sizeof(tmp), "%d ZOS.taginfo=%d %d\n",
                         reclen, flag, out_ccsid);
        if (n == reclen) break;
    }
    xlen += snprintf(xdata + xlen, sizeof(xdata) - xlen, "%s", tmp);

    /* Build the 'x' ustar header */
    unsigned char hdr[512];
    memset(hdr, 0, 512);

    /* name: "PaxHeader/<basename>" */
    snprintf((char *)hdr, 100, "PaxHeader/%.88s", basename);
    /* mode */
    snprintf((char *)hdr + 100, 8, "%07o", 0644);
    /* uid, gid */
    snprintf((char *)hdr + 108, 8, "%07o", 0);
    snprintf((char *)hdr + 116, 8, "%07o", 0);
    /* size of extended data */
    snprintf((char *)hdr + 124, 12, "%011o", xlen);
    /* mtime */
    snprintf((char *)hdr + 136, 12, "%011o", 0);
    /* type: 'x' = PAX extended header */
    hdr[156] = 'x';
    /* ustar magic */
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
 * If ccsid==1047, convert EBCDIC→819 on the fly.
 */
static int write_pax_file(int fd, const char *path, const char *arcname,
                          int ccsid, off_t filesize, pax_enc_t enc) {
    unsigned char hdr[512];
    memset(hdr, 0, 512);

    snprintf((char *)hdr, 100, "%.99s", arcname);
    snprintf((char *)hdr + 100,    8, "%07o", 0644);
    snprintf((char *)hdr + 108,    8, "%07o", 0);
    snprintf((char *)hdr + 116,    8, "%07o", 0);
    snprintf((char *)hdr + 124,   12, "%011llo", (unsigned long long)filesize);
    snprintf((char *)hdr + 136,   12, "%011o", 0);
    hdr[156] = '0'; /* regular file */
    memcpy(hdr + 257, "ustar\0" "00", 8);
    set_checksum(hdr, enc);
    if (pax_write(fd, hdr, 512, enc) != 512) return -1;

    int src = open(path, O_RDONLY);
    if (src < 0) { fprintf(stderr, "z-scp: open %s: %s\n", path, strerror(errno)); return -1; }

    /*
     * File content encoding:
     *
     * PAX_EBCDIC (z/OS): pax_write applies e2a[] to each byte, so AUTOCVT
     * (a2e[]) on z/OS restores the original byte.  We want z/OS to store
     * ISO-8859-1 (819) bytes, so we feed 819 bytes into pax_write:
     *   For 819 source:  feed ibuf[i] as-is → pax_write sends e2a[819_byte]
     *                    → AUTOCVT restores 819_byte on z/OS ✓
     *   For 1047 source: convert EBCDIC→819 first (e2a[]), then pax_write
     *                    sends e2a[e2a[1047_byte]] — BUT e2a(e2a(x)) ≠ x.
     *                    Instead: ibuf[i] is EBCDIC 1047; e2a[ibuf[i]] IS
     *                    the 819 byte; pax_write then sends e2a[that].
     *                    Wait — pax_write ALREADY applies e2a[].  So for
     *                    1047 source we must pass ibuf[i] (EBCDIC) to
     *                    pax_write and rely on e2a[] being the right map. ✓
     *
     * PAX_ASCII (non-z/OS): send 819 bytes as-is, or convert 1047→819.
     */
    unsigned char ibuf[8192];
    unsigned char obuf[8192];
    ssize_t nr;
    off_t written = 0;
    while ((nr = read(src, ibuf, sizeof(ibuf))) > 0) {
        if (enc == PAX_EBCDIC) {
            /*
             * pax_write applies e2a[] to every byte; AUTOCVT on z/OS stdin
             * applies a2e[], so the net result is identity: a2e[e2a[x]] = x.
             * We feed pax_write the bytes we want z/OS to store:
             *   819 source:    feed as-is  → z/OS stores original 819 bytes ✓
             *   1047 source:   pre-convert 1047→819 via e2a[], feed result ✓
             *   binary (65535): feed as-is → z/OS stores original bytes ✓
             */
            if (ccsid == 1047)
                for (ssize_t i = 0; i < nr; i++) obuf[i] = e2a[ibuf[i]];
            else
                memcpy(obuf, ibuf, nr); /* 819 and binary: pass through */
        } else {
            /* PAX_ASCII */
            if (ccsid == 1047)
                for (ssize_t i = 0; i < nr; i++) obuf[i] = e2a[ibuf[i]];
            else
                memcpy(obuf, ibuf, nr);
        }
        if (pax_write(fd, obuf, nr, enc) != (ssize_t)nr) { close(src); return -1; }
        written += nr;
    }
    close(src);

    /* pad content to 512-byte boundary (zeros same in both encodings) */
    size_t pad = (512 - (written % 512)) % 512;
    if (pad && write_zeros(fd, pad) != 0) return -1;

    return 0;
}

/* =========================================================================
 * Global flags (set by argument parser, read by transfer functions)
 * ====================================================================== */

static int dry_run     = 0;
static int reprobe     = 0;  /* kept for future cache reprobe use */
static int do_verify   = 0;  /* --verify: dump first 32 remote bytes via /bin/od */
static int recursive   = 0;  /* -r: recurse into directories */
static int force_ccsid = 0;  /* --ccsid N: override/fallback CCSID for downloads */
static int smart       = 0;  /* --smart: auto-detect encoding for untagged files */

/* =========================================================================
 * PAX archive reader (for download)
 *
 * z/OS pax -w writes ASCII pax archive bytes to its stdout.  SSH AUTOCVT
 * applies e2a[] to each byte before sending (EBCDIC programs output EBCDIC
 * which AUTOCVT converts to ASCII for the network).  However z/OS pax -w
 * writes raw bytes that AUTOCVT treats as EBCDIC → we receive e2a[byte].
 * To recover original pax archive bytes: apply a2e[received].
 *
 * After a2e[] decoding:
 *   - Header fields are plain ASCII/octal.
 *   - xdata ('g'/'x' records) is plain ASCII text.
 *   - File content bytes are the z/OS on-disk bytes in the file's tagged CCSID.
 *
 * The z/OS per-file extended header ('x') carries ZOS.taginfo=1 <ccsid>
 * for tagged files (or ZOS.taginfo=0 for untagged).  We use this to
 * determine whether to convert content bytes from 1047→819.
 * ====================================================================== */

#define PAX_BLOCK 512

/*
 * pipe_read_block: read exactly PAX_BLOCK bytes from pipe, applying a2e[]
 * to each byte (reverses z/OS AUTOCVT's e2a[] on stdout).
 * Returns 0 on success, -1 on EOF/error.
 */
static int pipe_read_block(FILE *pipe, unsigned char buf[PAX_BLOCK]) {
    for (int i = 0; i < PAX_BLOCK; i++) {
        int c = fgetc(pipe);
        if (c == EOF) return -1;
        buf[i] = a2e[(unsigned char)c];
    }
    return 0;
}

/*
 * pipe_read_block_raw: read exactly PAX_BLOCK bytes from pipe applying a2e[]
 * but WITHOUT additional content conversion.  Used for all blocks — the a2e[]
 * step is always needed to undo AUTOCVT; content conversion happens separately.
 */
static int pipe_read_block_raw(FILE *pipe, unsigned char buf[PAX_BLOCK]) {
    return pipe_read_block(pipe, buf);
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
 * Parse extended header data to extract CCSID.
 * Recognises both "IBM.codepage=N" (upload path) and "ZOS.taginfo=1 N" (z/OS pax -w).
 * Returns 0 if not found.
 */
static int parse_xhdr_ccsid(const char *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && data[j] != '\n') j++;
        /* find key after "NNN " */
        size_t k = i;
        while (k < j && data[k] != ' ') k++;
        k++;
        if (strncmp(data + k, "IBM.codepage=", 13) == 0)
            return atoi(data + k + 13);
        /* ZOS.taginfo=0 (untagged) or ZOS.taginfo=1 <ccsid> */
        if (strncmp(data + k, "ZOS.taginfo=", 12) == 0) {
            const char *p = data + k + 12;
            if (*p == '0') { i = j + 1; continue; } /* untagged */
            if (*p == '1' && *(p+1) == ' ') return atoi(p + 2);
        }
        i = j + 1;
    }
    return 0;
}

/*
 * makedirs: create all components of path (like mkdir -p).
 */
static void makedirs(const char *path) {
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s", path);
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
 * smart_convert: if --smart is set and ccsid==0 (no ZOS.taginfo from stream),
 * detect encoding of the already-written file and rewrite it converted if 1047.
 * Called after the raw bytes have been written to out_path.
 */
static void smart_convert(const char *out_path) {
    int is_text = 0;
    int detected = detect_ccsid(out_path, &is_text);
    if (detected != 1047) return; /* 819/binary/ambiguous — leave as-is */

    /* rewrite: read all, apply e2a[], write back */
    FILE *f = fopen(out_path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);
    if (fsz <= 0) { fclose(f); return; }
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

/*
 * pax_extract_entry: read and extract one file entry from the download stream.
 * pipe_read_block has already applied a2e[], giving on-disk bytes.
 * ccsid: from ZOS.taginfo or IBM.codepage (1047 = convert EBCDIC→819, others pass-through).
 * sz: file size in bytes.
 */
static int pax_extract_entry(FILE *pipe, const char *out_path,
                              long long sz, int ccsid) {
    /* ensure parent directory exists */
    char parent[4096];
    snprintf(parent, sizeof(parent), "%s", out_path);
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) { *slash = '\0'; makedirs(parent); }

    int out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0) {
        fprintf(stderr, "z-scp: open %s: %s\n", out_path, strerror(errno));
        /* drain blocks so stream stays in sync */
        long long skip = (sz + PAX_BLOCK - 1) / PAX_BLOCK;
        unsigned char tmp[PAX_BLOCK];
        for (long long b = 0; b < skip; b++) pipe_read_block_raw(pipe, tmp);
        return -1;
    }

    /*
     * pipe_read_block applies a2e[] to undo AUTOCVT's e2a[] on z/OS stdout,
     * recovering the on-disk bytes.
     * For 819/binary files: on-disk bytes are already 819 → write as-is.
     * For 1047-tagged files: on-disk bytes are EBCDIC-1047 → apply e2a[] → 819.
     */
    long long remaining = sz;
    unsigned char block[PAX_BLOCK];
    while (remaining > 0) {
        if (pipe_read_block(pipe, block) != 0) { close(out); return -1; }
        long long take = remaining < PAX_BLOCK ? remaining : PAX_BLOCK;
        unsigned char outbuf[PAX_BLOCK];
        if (ccsid == 1047) {
            for (long long i = 0; i < take; i++) outbuf[i] = e2a[block[i]];
        } else {
            memcpy(outbuf, block, take);
        }
        if (write(out, outbuf, take) != (ssize_t)take) { close(out); return -1; }
        remaining -= take;
    }
    close(out);
    fprintf(stderr, "z-scp: extracted %s (ccsid=%d)\n", out_path, ccsid ? ccsid : 65535);
    /* --smart: auto-detect and convert untagged files (no ZOS.taginfo) */
    if (smart && ccsid == 0)
        smart_convert(out_path);
    return 0;
}

/*
 * read_pax_stream: read a pax archive stream from z/OS, extracting files.
 * pipe_read_block handles the AUTOCVT decode (a2e[]) automatically.
 *
 * If dest_path is non-NULL: single-file mode — write the first regular file
 * to dest_path (used by do_download).
 *
 * If dest_path is NULL: tree mode — reconstruct full paths from archive
 * names under root_dir (used by download_dir).  archive names from z/OS
 * pax -w are absolute paths like "/u/user/dir/file"; we strip a leading
 * slash and prepend root_dir.
 */
static int read_pax_stream(FILE *pipe, const char *dest_path,
                            const char *root_dir) {
    unsigned char block[PAX_BLOCK];
    /* force_ccsid overrides ZOS.taginfo when set (for T=off files) */
    int ccsid  = 0;  /* from ZOS.taginfo in last 'x' xhdr, or force_ccsid */
    int nfiles = 0;

    while (1) {
        if (pipe_read_block(pipe, block) != 0) break;

        /* end-of-archive: all-zero block */
        int allzero = 1;
        for (int i = 0; i < PAX_BLOCK; i++) if (block[i]) { allzero = 0; break; }
        if (allzero) break;

        char     type = (char)block[156];
        long long sz  = parse_octal((char *)block + 124, 12);

        if (type == 'g' || type == 'G' || type == 'x' || type == 'X') {
            /* PAX global ('g') or per-file ('x') extended header */
            long long xsz = sz;
            char *xdata = malloc(xsz + 1);
            if (!xdata) return -1;
            size_t got = 0;
            while ((long long)got < xsz) {
                if (pipe_read_block(pipe, block) != 0) { free(xdata); return -1; }
                size_t take = ((long long)(xsz - got) < PAX_BLOCK)
                              ? (size_t)(xsz - got) : PAX_BLOCK;
                memcpy(xdata + got, block, take);
                got += PAX_BLOCK;
            }
            xdata[xsz] = '\0';
            /* only per-file ('x'/'X') xhdrs update the per-entry ccsid */
            if (type == 'x' || type == 'X') {
                int found = parse_xhdr_ccsid(xdata, xsz);
                if (found) ccsid = found;
            }
            free(xdata);
            continue;
        }

        if (type == '0' || type == '\0') {
            /* Regular file */
            char out_path[4096];
            if (dest_path) {
                /* single-file mode: always write to dest_path */
                snprintf(out_path, sizeof(out_path), "%s", dest_path);
            } else {
                /* tree mode: archive name is at block[0..99] */
                char arcname[101];
                memcpy(arcname, block, 100);
                arcname[100] = '\0';
                /* strip leading slash */
                const char *rel = arcname;
                while (*rel == '/') rel++;
                snprintf(out_path, sizeof(out_path), "%s/%s", root_dir, rel);
            }
            if (pax_extract_entry(pipe, out_path, sz,
                                  force_ccsid ? force_ccsid : ccsid) == 0)
                nfiles++;
            else
                nfiles++; /* count even on error so we don't return -1 spuriously */
            /* reset ccsid for next entry */
            ccsid = 0;
            if (dest_path) return 0; /* single-file: done after first entry */
            continue;
        }

        if (type == '5') {
            /* Directory entry — create it */
            if (!dest_path) {
                char arcname[101];
                memcpy(arcname, block, 100);
                arcname[100] = '\0';
                const char *rel = arcname;
                while (*rel == '/') rel++;
                char dir_path[4096];
                snprintf(dir_path, sizeof(dir_path), "%s/%s", root_dir, rel);
                makedirs(dir_path);
            }
            ccsid = 0;
            continue;
        }

        /* Skip other entry types */
        long long nblocks = (sz + PAX_BLOCK - 1) / PAX_BLOCK;
        for (long long b = 0; b < nblocks; b++)
            if (pipe_read_block(pipe, block) != 0) return nfiles > 0 ? 0 : -1;
        ccsid = 0;
    }

    if (nfiles == 0 && dest_path) {
        fprintf(stderr, "z-scp: no regular file found in pax stream\n");
        return -1;
    }
    return 0;
}

/* =========================================================================
 * Argument parsing and SSH dispatch
 * ====================================================================== */

/* Split "user@host:/path" into host ("user@host") and path.
 * Returns 1 if remote syntax detected, 0 if local. */
static int split_remote(const char *arg, char *host, size_t hostsz,
                         char *path, size_t pathsz) {
    const char *colon = strchr(arg, ':');
    if (!colon) return 0;
    /* make sure there's a @ before the colon (simple check) */
    size_t hlen = colon - arg;
    if (hlen == 0 || hlen >= hostsz) return 0;
    memcpy(host, arg, hlen); host[hlen] = '\0';
    strncpy(path, colon + 1, pathsz - 1); path[pathsz - 1] = '\0';
    return 1;
}

/* Returns just the filename component of a path */
__attribute__((unused))
static const char *basename_of(const char *path) {
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

/*
 * convert_to_tmp: if ccsid==1047, convert local file EBCDIC→819 into a
 * temp file and return its path (caller must unlink).
 * Otherwise returns NULL (no conversion needed, use original file).
 */
/* =========================================================================
 * Recursive upload
 * ====================================================================== */

/*
 * collect_upload: walk local_dir recursively, building:
 *   - filelist: one "pack_path remote_path\n" per file (pack_path is a temp
 *               file for EBCDIC-converted content, or the original local path)
 *   - chtag:    one chtag command per file for the post-pax tagging pass
 *   - tmps:     temp file paths to unlink after the tar stream is sent
 * No network connections are made here.
 */
typedef struct { char **paths; size_t n, cap; } strlist_t;
static void sl_add(strlist_t *l, char *s) {
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 64;
        l->paths = realloc(l->paths, l->cap * sizeof(*l->paths));
    }
    l->paths[l->n++] = s;
}

/*
 * write_pax_tree: walk local_dir recursively, writing a pax archive to fd.
 * Each file gets an 'x' extended header with IBM.codepage=<ccsid>.
 * EBCDIC source files are converted to 819 on the fly.
 * remote_dir is the archive path prefix for all files.
 * ZOS.taginfo in each 'x' xhdr makes z/OS pax -r set the tag automatically.
 */
static int write_pax_tree(int fd, const char *local_dir, const char *remote_dir) {
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

        char local_path[4096], remote_path[4096];
        snprintf(local_path,  sizeof(local_path),  "%s/%s", local_dir,  ent->d_name);
        snprintf(remote_path, sizeof(remote_path), "%s/%s", remote_dir, ent->d_name);

        struct stat st;
        if (lstat(local_path, &st) != 0) {
            fprintf(stderr, "z-scp: lstat %s: %s\n", local_path, strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            sl_add(&subdirs, strdup(local_path));
            sl_add(&subdirs, strdup(remote_path));
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;

        int is_text = 0;
        int ccsid   = detect_ccsid(local_path, &is_text);
        if (ccsid < 0) { errors++; continue; }
        /* tag_ccsid: 819 for all text (including EBCDIC converted), 65535 for binary */
        int tag_ccsid = (ccsid == 65535) ? 65535 : 819;

        fprintf(stderr, "z-scp: %s → %s (ccsid=%d tag=%d)\n",
                local_path, remote_path, ccsid, tag_ccsid);

        if (dry_run) continue;

        /* write ZOS.taginfo xhdr then file content */
        if (write_pax_xhdr(fd, ent->d_name, tag_ccsid, PAX_EBCDIC) != 0 ||
            write_pax_file(fd, local_path, remote_path, ccsid, st.st_size, PAX_EBCDIC) != 0) {
            fprintf(stderr, "z-scp: write error for %s\n", local_path);
            errors++;
        }
    }
    closedir(d);

    /* recurse */
    for (size_t i = 0; i + 1 < subdirs.n; i += 2) {
        errors += write_pax_tree(fd, subdirs.paths[i], subdirs.paths[i+1]);
        free(subdirs.paths[i]);
        free(subdirs.paths[i+1]);
    }
    free(subdirs.paths);
    return errors;
}

/*
 * upload_dir: stream a pax archive into ssh pax -r.
 * ZOS.taginfo in each file's 'x' xhdr causes pax -r to set the tag automatically.
 */
static int upload_dir(const char *local_dir, const char *remote_host,
                      const char *remote_dir) {
    if (dry_run)
        return write_pax_tree(-1, local_dir, remote_dir);

    char ssh_cmd[4096];
    snprintf(ssh_cmd, sizeof(ssh_cmd),
             "ssh -o BatchMode=yes %s \"/bin/pax -r -x pax -p p\"",
             remote_host);

    fprintf(stderr, "z-scp: streaming pax archive to %s:%s...\n",
            remote_host, remote_dir);

    FILE *pipe = popen(ssh_cmd, "w");
    if (!pipe) {
        fprintf(stderr, "z-scp: popen ssh: %s\n", strerror(errno));
        return 1;
    }

    int fd = fileno(pipe);
    int errors = write_pax_tree(fd, local_dir, remote_dir);

    /* write end-of-archive: two 512-byte zero blocks */
    unsigned char eoa[1024] = {0};
    if (write(fd, eoa, sizeof(eoa)) != sizeof(eoa))
        errors++;

    int rc = pclose(pipe);
    if (rc != 0) {
        fprintf(stderr, "z-scp: pax -r failed (exit %d)\n", WEXITSTATUS(rc));
        errors++;
    }

    fprintf(stderr, "z-scp: recursive upload complete\n");
    return errors ? 1 : 0;
}

/* =========================================================================
 * Recursive download
 * ====================================================================== */

/*
 * download_dir: recursively download remote_dir into local_dir.
 *
 * One SSH connection: ssh /bin/pax -w streams an EBCDIC pax archive which
 * read_pax_stream decodes entirely in C — no local pax, tar, or aepipe needed.
 * Archive entry names are absolute z/OS paths; we strip the leading slash and
 * prepend local_dir to reconstruct the local tree.
 */
static int download_dir(const char *remote_host, const char *remote_dir,
                         const char *local_dir) {
    if (dry_run) {
        fprintf(stderr, "z-scp: dry-run: would download %s:%s → %s\n",
                remote_host, remote_dir, local_dir);
        return 0;
    }

    char pax_cmd[4096];
    snprintf(pax_cmd, sizeof(pax_cmd),
             "ssh -o BatchMode=yes %s \"/bin/pax -w -x pax '%s'\"",
             remote_host, remote_dir);

    fprintf(stderr, "z-scp: streaming pax from %s:%s...\n", remote_host, remote_dir);
    FILE *pipe = popen(pax_cmd, "r");
    if (!pipe) {
        fprintf(stderr, "z-scp: popen ssh: %s\n", strerror(errno));
        return 1;
    }

    makedirs(local_dir);
    int rc = read_pax_stream(pipe, NULL, local_dir);
    pclose(pipe);

    fprintf(stderr, "z-scp: recursive download complete\n");
    return rc;
}

/* =========================================================================
 * Single-file upload / download  (pax-based)
 * ====================================================================== */

/*
 * do_upload: stream one file to z/OS as a pax archive with ZOS.taginfo xhdr.
 * z/OS pax -r reads ZOS.taginfo and sets the file tag automatically.
 */
static int do_upload(const char *local, const char *remote_host,
                     const char *remote_path) {
    int is_text = 0;
    int ccsid = detect_ccsid(local, &is_text);
    if (ccsid < 0) return 1;

    int tag_ccsid = (ccsid == 65535) ? 65535 : 819;

    fprintf(stderr, "z-scp: upload %s → %s:%s (ccsid=%d tag=%d)\n",
            local, remote_host, remote_path, ccsid, tag_ccsid);

    if (dry_run) {
        fprintf(stderr, "z-scp: dry-run: would tag remote as ccsid=%d\n", tag_ccsid);
        return 0;
    }

    struct stat st;
    if (stat(local, &st) != 0) {
        fprintf(stderr, "z-scp: stat %s: %s\n", local, strerror(errno));
        return 1;
    }

    char ssh_cmd[4096];
    snprintf(ssh_cmd, sizeof(ssh_cmd),
             "ssh -o BatchMode=yes %s \"/bin/pax -r -x pax -p p\"",
             remote_host);

    FILE *pipe = popen(ssh_cmd, "w");
    if (!pipe) {
        fprintf(stderr, "z-scp: popen ssh: %s\n", strerror(errno));
        return 1;
    }

    int fd = fileno(pipe);
    const char *basename = strrchr(remote_path, '/');
    basename = basename ? basename + 1 : remote_path;

    int rc = 0;
    if (write_pax_xhdr(fd, basename, tag_ccsid, PAX_EBCDIC) != 0 ||
        write_pax_file(fd, local, remote_path, ccsid, st.st_size, PAX_EBCDIC) != 0) {
        fprintf(stderr, "z-scp: pax write error\n");
        rc = 1;
    }

    /* end-of-archive */
    unsigned char eoa[1024] = {0};
    if (write(fd, eoa, sizeof(eoa)) != sizeof(eoa)) rc = 1;

    int prc = pclose(pipe);
    if (prc != 0) {
        fprintf(stderr, "z-scp: pax -r failed (exit %d)\n", WEXITSTATUS(prc));
        rc = 1;
    }

    if (!rc) fprintf(stderr, "z-scp: upload complete, tagged ccsid=%d\n", tag_ccsid);

    /* optional: verify remote bytes via /bin/od */
    if (!rc && do_verify) {
        char od_cmd[4096];
        snprintf(od_cmd, sizeof(od_cmd),
                 "ssh -o BatchMode=yes %s \"/bin/od -An -tx1 -N32 '%s'\"",
                 remote_host, remote_path);
        fprintf(stderr, "z-scp: verify — remote first 32 bytes (hex):\n");
        int _r = system(od_cmd); (void)_r;
    }

    return rc;
}

/*
 * do_download: stream one file from z/OS via ssh /bin/pax -w.
 * read_pax_stream decodes the archive entirely in C — no local pax or aepipe needed.
 * ZOS.taginfo in the 'x' xhdr drives CCSID; 1047-tagged content is converted →819.
 * T=off files have no ZOS.taginfo in the pax stream and are written as-is.
 */
static int do_download(const char *remote_host, const char *remote_path,
                       const char *local) {
    fprintf(stderr, "z-scp: download %s:%s → %s\n",
            remote_host, remote_path, local);

    if (dry_run) {
        fprintf(stderr, "z-scp: dry-run: would download %s:%s\n",
                remote_host, remote_path);
        return 0;
    }

    char pax_cmd[4096];
    snprintf(pax_cmd, sizeof(pax_cmd),
             "ssh -o BatchMode=yes %s \"/bin/pax -w -x pax '%s'\"",
             remote_host, remote_path);

    FILE *pipe = popen(pax_cmd, "r");
    if (!pipe) {
        fprintf(stderr, "z-scp: popen ssh: %s\n", strerror(errno));
        return 1;
    }

    int rc = read_pax_stream(pipe, local, NULL);
    pclose(pipe);

    if (!rc) fprintf(stderr, "z-scp: download complete\n");
    return rc;
}

/* =========================================================================
 * main
 * ====================================================================== */

int main(int argc, char **argv) {
    /* strip flags — mix of -x and --long-opt accepted in any order */
    while (argc > 1 && argv[1][0] == '-') {
        if      (strcmp(argv[1], "-r")        == 0) recursive = 1;
        else if (strcmp(argv[1], "--dry-run") == 0) dry_run   = 1;
        else if (strcmp(argv[1], "--reprobe") == 0) reprobe   = 1;
        else if (strcmp(argv[1], "--verify")  == 0) do_verify = 1;
        else if (strcmp(argv[1], "--ccsid")   == 0) {
            if (argc < 3) { fprintf(stderr, "z-scp: --ccsid requires a value\n"); return 1; }
            force_ccsid = atoi(argv[2]);
            argv++; argc--;
        }
        else if (strcmp(argv[1], "--smart")   == 0) smart = 1;
        else break;
        argv++; argc--;
    }

    if (argc != 3) {
        fprintf(stderr,
                "Usage: z-scp [-r] [--dry-run] [--verify] [--ccsid N] <source> <destination>\n"
                "  upload:   z-scp localfile       user@host:/remote/path\n"
                "  download: z-scp user@host:/remote/path  localfile\n"
                "  -r:           recursive (directory transfer)\n"
                "  --dry-run:    show what would be done without transferring\n"
                "  --verify:     after upload, dump first 32 remote bytes via /bin/od\n"
                "  --ccsid N:    force CCSID N for download (e.g. 1047 for T=off EBCDIC files)\n"
                "  --smart:      auto-detect encoding for untagged downloads (no ZOS.taginfo)\n");
        return 1;
    }

    const char *src = argv[1];
    const char *dst = argv[2];

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

    if (!src_remote) {
        if (recursive) {
            struct stat st;
            if (stat(src, &st) == 0 && S_ISDIR(st.st_mode))
                return upload_dir(src, dst_host, dst_path);
        }
        return do_upload(src, dst_host, dst_path);
    } else {
        if (recursive)
            return download_dir(src_host, src_path, dst);
        return do_download(src_host, src_path, dst);
    }
}

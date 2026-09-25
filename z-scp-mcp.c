/*
 * z-scp-mcp.c — MCP stdio server exposing z-scp to LLM agents.
 *
 * Transport : stdio (newline-delimited JSON-RPC 2.0)
 * Tools     :
 *   zscp_transfer  — run a z-scp upload/download (full flag coverage)
 *   zscp_detect    — detect local file encoding (1047 / 819 / binary)
 *   zscp_meta_read — read a .z-scp-meta.json sidecar
 *   zscp_help      — usage summary
 *
 * No external dependencies — JSON is built/parsed by hand.
 * stdout carries only protocol JSON; all logging goes to stderr.
 *
 * z-scp binary resolution order:
 *   1. $ZSCP_BIN (explicit path)
 *   2. <exedir>/z-scp (sibling of this binary — normal install)
 *   3. ./z-scp (project cwd, e.g. when launched via ["./z-scp-mcp"])
 *   4. "z-scp" via $PATH (execvp fallback)
 *
 * Build: gcc -std=c11 -Wall -Wextra -O2 -o z-scp-mcp z-scp-mcp.c
 */

#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Buffer helpers
 * ---------------------------------------------------------------------- */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} Buf;

static void buf_init(Buf *b) {
    b->cap = 4096;
    b->len = 0;
    b->data = malloc(b->cap);
    if (b->data) b->data[0] = '\0';
}

static void buf_free(Buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static void buf_reserve(Buf *b, size_t extra) {
    while (b->len + extra + 1 > b->cap) {
        b->cap *= 2;
        b->data = realloc(b->data, b->cap);
    }
}

static void buf_append(Buf *b, const char *s) {
    size_t slen = strlen(s);
    buf_reserve(b, slen);
    memcpy(b->data + b->len, s, slen + 1);
    b->len += slen;
}

static void buf_append_n(Buf *b, const char *s, size_t n) {
    buf_reserve(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

/* Append src JSON-escaped (without surrounding quotes). */
static void buf_append_escaped(Buf *b, const char *src) {
    static const char *hexd = "0123456789abcdef";
    for (; *src; src++) {
        unsigned char c = (unsigned char)*src;
        switch (c) {
        case '"':  buf_append(b, "\\\""); break;
        case '\\': buf_append(b, "\\\\"); break;
        case '\n': buf_append(b, "\\n"); break;
        case '\r': buf_append(b, "\\r"); break;
        case '\t': buf_append(b, "\\t"); break;
        default:
            if (c < 0x20) {
                char u[7];
                u[0] = '\\'; u[1] = 'u'; u[2] = '0'; u[3] = '0';
                u[4] = hexd[(c >> 4) & 0xf]; u[5] = hexd[c & 0xf]; u[6] = '\0';
                buf_append(b, u);
            } else {
                buf_reserve(b, 1);
                b->data[b->len++] = (char)c;
                b->data[b->len] = '\0';
            }
        }
    }
}

/* -------------------------------------------------------------------------
 * Minimal JSON getters (flat-object subset, enough for MCP requests)
 * ---------------------------------------------------------------------- */

static int json_get_string(const char *json, const char *key,
                           char *out, size_t outsz) {
    char needle[160];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' ||
                  *p == '\r' || *p == ':')) p++;
    if (*p == 'n' && strncmp(p, "null", 4) == 0) return 0;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\') {
            p++;
            switch (*p) {
            case '"': case '\\': case '/': out[i++] = *p; break;
            case 'n': out[i++] = '\n'; break;
            case 'r': out[i++] = '\r'; break;
            case 't': out[i++] = '\t'; break;
            case 'u': {
                /* Best-effort \uXXXX → '?' for non-ASCII; ASCII kept. */
                char hb[5] = {0};
                memcpy(hb, p + 1, 4);
                unsigned v = 0;
                if (sscanf(hb, "%x", &v) == 1 && v < 0x80)
                    out[i++] = (char)v;
                else if (i + 1 < outsz)
                    out[i++] = '?';
                p += 4;
                break;
            }
            case '\0': goto done;
            default: out[i++] = *p; break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
done:
    out[i] = '\0';
    return 1;
}

/* Parse true/false/1/0 for key. Returns 1 if found, sets *out. */
static int json_get_bool(const char *json, const char *key, int *out) {
    char needle[160];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if (strncmp(p, "true", 4) == 0) { *out = 1; return 1; }
    if (strncmp(p, "false", 5) == 0) { *out = 0; return 1; }
    if (*p == '1' && !isdigit((unsigned char)p[1])) { *out = 1; return 1; }
    if (*p == '0' && !isdigit((unsigned char)p[1])) { *out = 0; return 1; }
    return 0;
}

static int json_get_number(const char *json, const char *key, double *out) {
    char needle[160];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if (!(*p == '-' || *p == '+' || isdigit((unsigned char)*p))) return 0;
    char *end = NULL;
    double v = strtod(p, &end);
    if (end == p) return 0;
    *out = v;
    return 1;
}

/* Extract "id" as raw JSON token (number, string, or null). */
static void json_get_id(const char *json, char *out, size_t outsz) {
    const char *p = strstr(json, "\"id\"");
    if (!p) { snprintf(out, outsz, "null"); return; }
    p += 4;
    while (*p && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if (!*p) { snprintf(out, outsz, "null"); return; }
    size_t i = 0;
    if (*p == '"') {
        out[i++] = *p++;
        while (*p && i + 1 < outsz) {
            if (*p == '\\') {
                out[i++] = *p++;
                if (*p && i + 1 < outsz) out[i++] = *p++;
                continue;
            }
            out[i++] = *p;
            if (*p++ == '"') break;
        }
        out[i] = '\0';
        return;
    }
    while (*p && i + 1 < outsz) {
        if (*p == ',' || *p == '}' || *p == ']' ||
            *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            break;
        out[i++] = *p++;
    }
    out[i] = '\0';
    if (!i) snprintf(out, outsz, "null");
}

/* Locate the "arguments" object; returns pointer to '{' or NULL. */
static const char *find_arguments(const char *req) {
    const char *params = strstr(req, "\"params\"");
    if (!params) return NULL;
    const char *a = strstr(params, "\"arguments\"");
    if (!a) return NULL;
    return strchr(a, '{');
}

/* -------------------------------------------------------------------------
 * Response builders (stdout only)
 * ---------------------------------------------------------------------- */

static void send_line(const char *json) {
    fputs(json, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static void send_error(const char *id, int code, const char *message) {
    Buf b; buf_init(&b);
    buf_append(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    buf_append(&b, id);
    buf_append(&b, ",\"error\":{\"code\":");
    char cb[32]; snprintf(cb, sizeof(cb), "%d", code);
    buf_append(&b, cb);
    buf_append(&b, ",\"message\":\"");
    buf_append_escaped(&b, message);
    buf_append(&b, "\"}}");
    send_line(b.data);
    buf_free(&b);
}

static void send_result(const char *id, const char *result_json) {
    Buf b; buf_init(&b);
    buf_append(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    buf_append(&b, id);
    buf_append(&b, ",\"result\":");
    buf_append(&b, result_json);
    buf_append(&b, "}");
    send_line(b.data);
    buf_free(&b);
}

/* Standard tool result. is_error=1 sets isError:true. */
static void tool_result(const char *id, const char *text, int is_error) {
    Buf r; buf_init(&r);
    buf_append(&r, "{\"content\":[{\"type\":\"text\",\"text\":\"");
    buf_append_escaped(&r, text);
    buf_append(&r, "\"}]");
    if (is_error) buf_append(&r, ",\"isError\":true");
    buf_append(&r, "}");
    send_result(id, r.data);
    buf_free(&r);
}

/* -------------------------------------------------------------------------
 * z-scp binary resolution + runner
 * ---------------------------------------------------------------------- */

static const char *g_argv0 = "z-scp-mcp";
static char g_zscp_path[PATH_MAX] = {0};

static int file_is_exec(const char *p) {
    struct stat st;
    return (stat(p, &st) == 0 && (st.st_mode & S_IXUSR));
}

/* Resolve once at startup; returns path to use with exec (may be "z-scp"). */
static const char *resolve_zscp(void) {
    if (g_zscp_path[0]) return g_zscp_path;

    const char *env = getenv("ZSCP_BIN");
    if (env && *env) {
        snprintf(g_zscp_path, sizeof(g_zscp_path), "%s", env);
        return g_zscp_path;
    }
    /* <exedir>/z-scp via /proc/self/exe (Linux). */
    char exe[PATH_MAX] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
        char *slash = strrchr(exe, '/');
        if (slash) {
            char cand[PATH_MAX];
            snprintf(cand, sizeof(cand), "%.*s/z-scp",
                     (int)(slash - exe), exe);
            if (file_is_exec(cand)) {
                snprintf(g_zscp_path, sizeof(g_zscp_path), "%s", cand);
                return g_zscp_path;
            }
        }
    }
    /* argv[0] directory fallback (covers ./z-scp-mcp launches). */
    if (g_argv0 && strchr(g_argv0, '/')) {
        const char *slash = strrchr(g_argv0, '/');
        char cand[PATH_MAX];
        size_t dlen = (size_t)(slash - g_argv0);
        if (dlen + 7 < sizeof(cand)) {
            memcpy(cand, g_argv0, dlen);
            memcpy(cand + dlen, "/z-scp", 7);
            if (file_is_exec(cand)) {
                snprintf(g_zscp_path, sizeof(g_zscp_path), "%s", cand);
                return g_zscp_path;
            }
        }
    }
    /* cwd ./z-scp  */
    if (file_is_exec("./z-scp")) {
        snprintf(g_zscp_path, sizeof(g_zscp_path), "./z-scp");
        return g_zscp_path;
    }
    /* PATH fallback — execvp resolves it. */
    snprintf(g_zscp_path, sizeof(g_zscp_path), "z-scp");
    return g_zscp_path;
}

/* Run argv (NULL-terminated), capture combined stdout+stderr into out.
 * Returns exit code, or -1 on spawn/read failure. */
static int run_external(char *const argv[], Buf *out) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        buf_append(out, "pipe() failed: ");
        buf_append(out, strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        buf_append(out, "fork() failed: ");
        buf_append(out, strerror(errno));
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        /* argv[0] may be a path or bare name; execvp handles both. */
        execvp(argv[0], argv);
        fprintf(stderr, "execvp(%s) failed: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    close(pipefd[1]);
    char chunk[4096];
    ssize_t nr;
    while ((nr = read(pipefd[0], chunk, sizeof(chunk))) > 0)
        buf_append_n(out, chunk, (size_t)nr);
    close(pipefd[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

/* -------------------------------------------------------------------------
 * Encoding detection (same tables as z-scp.c / tagfile.c)
 * ---------------------------------------------------------------------- */

static const char ebcdic_valid[256] = {
    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
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

/* Returns ccsid (1047/819/65535), matching z-scp.c detect_ccsid exactly.
 * *is_text is 1 for tagged text, 0 for binary/untagged. -1 on open error. */
static int detect_ccsid(const char *path, int *is_text) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t eb_cnt = 0, tot = 0, asc_cnt = 0;
    int utf8_st = 1, utf8_err = 0; /* 1 == onebyte (start) */
    unsigned char chunk[8192];
    ssize_t n;
    while ((n = read(fd, chunk, sizeof(chunk))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            if (ebcdic_valid[chunk[i]]) eb_cnt++;
            if (ascii_valid[chunk[i]]) asc_cnt++;
            tot++;
        }
        /* UTF-8 state machine over the same bytes */
        for (ssize_t i = 0; i < n && utf8_st != 8; i++) {
            int p = utf8pat[chunk[i]];
            switch (utf8_st) {
            case 1: /* onebyte */
                if (p == 9 || p == 1) utf8_st = 8;
                else if (p == 2) utf8_st = 5; /* twobyte0 */
                else if (p == 3) utf8_st = 6; /* threebyte0 */
                else if (p == 4) utf8_st = 7; /* fourbyte0 (then sub-states) */
                break;
            case 5: utf8_st = (p == 1) ? 1 : 8; break;
            case 6: utf8_st = (p == 1) ? 9 : 8; break;  /* threebyte1 = 9 */
            case 9: utf8_st = (p == 1) ? 1 : 8; break;
            case 7: utf8_st = (p == 1) ? 10 : 8; break; /* fourbyte1 = 10 */
            case 10: utf8_st = (p == 1) ? 11 : 8; break;/* fourbyte2 = 11 */
            case 11: utf8_st = (p == 1) ? 1 : 8; break;
            default: utf8_st = 8;
            }
        }
        if (utf8_st == 8) utf8_err = 1;
    }
    close(fd);
    if (tot == 0) { *is_text = 0; return 65535; }
    if (eb_cnt == tot) { *is_text = 1; return 1047; }
    if (asc_cnt == tot) { *is_text = 1; return 819; }
    if (asc_cnt > 0 && !utf8_err && utf8_st == 1) {
        *is_text = 1; return 819;
    }
    if (eb_cnt > 0 && (eb_cnt * 105) / (tot * 100) > 0) {
        *is_text = 0; return 1047;
    }
    if (asc_cnt > 0 && (asc_cnt * 105) / (tot * 100) > 0) {
        *is_text = 0; return 819;
    }
    *is_text = 0;
    return 65535;
}

/* -------------------------------------------------------------------------
 * MCP method handlers
 * ---------------------------------------------------------------------- */

#define SERVER_NAME "z-scp-mcp"
#define SERVER_VERSION "1.0.0"

static void handle_initialize(const char *id, const char *req) {
    (void)req;
    send_result(id,
        "{"
          "\"protocolVersion\":\"2024-11-05\","
          "\"capabilities\":{\"tools\":{}},"
          "\"serverInfo\":{\"name\":\"" SERVER_NAME "\","
                         "\"version\":\"" SERVER_VERSION "\"}"
        "}");
}

static void handle_tools_list(const char *id, const char *req) {
    (void)req;
    send_result(id,
        "{"
          "\"tools\":["
            "{"
              "\"name\":\"zscp_transfer\","
              "\"description\":\"Transfer a file or directory to/from z/OS over SSH using z-scp (pax stream, EBCDIC/tag aware). "
                "Direction is inferred: use user@host:/path for the z/OS side and a plain path for the local side. "
                "Upload example: source=localfile.c destination=user@host:/u/me/localfile.c. "
                "Download example: source=user@host:/u/me/log destination=./log. "
                "Set recursive=true for directories. "
                "Use dry_run=true to preview without transferring. "
                "Use meta=true (or meta_file) to preserve z/OS attributes across round-trips.\","
              "\"inputSchema\":{"
                "\"type\":\"object\","
                "\"properties\":{"
                  "\"source\":{\"type\":\"string\",\"description\":\"Source path (user@host:/path for z/OS, plain path for local).\"},"
                  "\"destination\":{\"type\":\"string\",\"description\":\"Destination path (user@host:/path for z/OS, plain path for local).\"},"
                  "\"recursive\":{\"type\":\"boolean\",\"description\":\"Recursive directory transfer (-r). Default false.\"},"
                  "\"dry_run\":{\"type\":\"boolean\",\"description\":\"Show what would be done without transferring (--dry-run). Default false.\"},"
                  "\"verify\":{\"type\":\"boolean\",\"description\":\"After upload, dump first 32 remote bytes via /bin/od (--verify). Default false.\"},"
                  "\"smart\":{\"type\":\"boolean\",\"description\":\"Auto-detect encoding for untagged downloads (--smart). Default false.\"},"
                  "\"ccsid\":{\"type\":\"number\",\"description\":\"Force CCSID for download conversion (--ccsid N, e.g. 1047). Omit or 0 for auto.\"},"
                  "\"meta\":{\"type\":\"boolean\",\"description\":\"Read/write .z-scp-meta.json alongside local files (--meta). Default false. Mutually exclusive with meta_file.\"},"
                  "\"meta_file\":{\"type\":\"string\",\"description\":\"Explicit meta file path (--meta-file F). Mutually exclusive with meta.\"},"
                  "\"reprobe\":{\"type\":\"boolean\",\"description\":\"Refresh cached PAX-header probe for the host (--reprobe). Default false.\"}"
                "},"
                "\"required\":[\"source\",\"destination\"]"
              "}"
            "},"
            "{"
              "\"name\":\"zscp_detect\","
              "\"description\":\"Detect the encoding of a LOCAL file (EBCDIC-1047, ISO-8859-1/819, or binary/65535) using z-scp's classifier. "
                "Use before upload to predict the CCSID/tag decision, or to inspect a downloaded file.\","
              "\"inputSchema\":{"
                "\"type\":\"object\","
                "\"properties\":{"
                  "\"path\":{\"type\":\"string\",\"description\":\"Local file path to classify.\"}"
                "},"
                "\"required\":[\"path\"]"
              "}"
            "},"
            "{"
              "\"name\":\"zscp_meta_read\","
              "\"description\":\"Read a z-scp meta sidecar (.z-scp-meta.json) and return its contents. "
                "The meta file records z/OS-specific attributes (CCSID, T=on/off tag, mode, mtime, extattr, audit flags) captured on download.\","
              "\"inputSchema\":{"
                "\"type\":\"object\","
                "\"properties\":{"
                  "\"path\":{\"type\":\"string\",\"description\":\"Path to the meta JSON file.\"}"
                "},"
                "\"required\":[\"path\"]"
              "}"
            "},"
            "{"
              "\"name\":\"zscp_help\","
              "\"description\":\"Return z-scp usage, options, and encoding/tagging notes.\","
              "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}"
            "}"
          "]"
        "}");
}

static void handle_transfer(const char *id, const char *args) {
    char source[4096] = {0}, dest[4096] = {0}, meta_file[4096] = {0};
    int recursive = 0, dry_run = 0, verify = 0, smart = 0;
    int meta = 0, reprobe = 0;
    double ccsid_d = 0;
    int has_ccsid = json_get_number(args, "ccsid", &ccsid_d);

    json_get_string(args, "source", source, sizeof(source));
    json_get_string(args, "destination", dest, sizeof(dest));
    json_get_string(args, "meta_file", meta_file, sizeof(meta_file));
    json_get_bool(args, "recursive", &recursive);
    json_get_bool(args, "dry_run", &dry_run);
    json_get_bool(args, "verify", &verify);
    json_get_bool(args, "smart", &smart);
    json_get_bool(args, "meta", &meta);
    json_get_bool(args, "reprobe", &reprobe);

    if (!source[0] || !dest[0]) {
        send_error(id, -32602, "zscp_transfer requires source and destination");
        return;
    }
    if (meta && meta_file[0]) {
        send_error(id, -32602, "meta and meta_file are mutually exclusive");
        return;
    }
    long ccsid = has_ccsid ? (long)ccsid_d : 0;
    if ((has_ccsid && ccsid_d != (double)ccsid) || ccsid < 0 || ccsid > 65535) {
        send_error(id, -32602, "ccsid must be an integer 1..65535 (or omit)");
        return;
    }

    const char *bin = resolve_zscp();

    /* argv: bin + 8 possible flags + --ccsid N + --meta-file F + src + dst */
    char *argv[16];
    char ccsid_s[16];
    int ac = 0;
    argv[ac++] = (char *)bin;
    if (recursive) argv[ac++] = "-r";
    if (dry_run)   argv[ac++] = "--dry-run";
    if (verify)    argv[ac++] = "--verify";
    if (smart)     argv[ac++] = "--smart";
    if (ccsid > 0) {
        argv[ac++] = "--ccsid";
        snprintf(ccsid_s, sizeof(ccsid_s), "%ld", ccsid);
        argv[ac++] = ccsid_s;
    }
    if (meta) argv[ac++] = "--meta";
    if (meta_file[0]) { argv[ac++] = "--meta-file"; argv[ac++] = meta_file; }
    if (reprobe) argv[ac++] = "--reprobe";
    argv[ac++] = source;
    argv[ac++] = dest;
    argv[ac] = NULL;

    Buf out; buf_init(&out);
    int rc = run_external(argv, &out);

    Buf txt; buf_init(&txt);
    char head[128];
    snprintf(head, sizeof(head), "exit code: %d\ncommand: %s",
             rc, bin);
    buf_append(&txt, head);
    /* echo effective flags for agent visibility */
    char flags[256];
    snprintf(flags, sizeof(flags),
             " [recursive=%d dry_run=%d verify=%d smart=%d ccsid=%ld meta=%d%s%s reprobe=%d]\n",
             recursive, dry_run, verify, smart, ccsid, meta,
             meta_file[0] ? " meta_file=" : "", meta_file[0] ? meta_file : "",
             reprobe);
    buf_append(&txt, flags);
    buf_append(&txt, out.data ? out.data : "");
    tool_result(id, txt.data, rc != 0);
    buf_free(&out);
    buf_free(&txt);
}

static void handle_detect(const char *id, const char *args) {
    char path[4096] = {0};
    json_get_string(args, "path", path, sizeof(path));
    if (!path[0]) {
        send_error(id, -32602, "zscp_detect requires path");
        return;
    }
    int is_text = 0;
    int ccsid = detect_ccsid(path, &is_text);
    if (ccsid < 0) {
        char msg[4200];
        snprintf(msg, sizeof(msg), "cannot open %s: %s", path, strerror(errno));
        tool_result(id, msg, 1);
        return;
    }
    struct stat st;
    long long size = -1;
    if (stat(path, &st) == 0) size = (long long)st.st_size;
    char txt[4600];
    snprintf(txt, sizeof(txt),
             "path: %s\nccsid: %d (%s)\ntag: %s\nsize: %lld bytes\n"
             "note: on upload without meta, ccsid 1047 is stored as-is under T=on, "
             "819/binary transferred as-is; with meta 1047 the file is converted back to EBCDIC.",
             path, ccsid,
             ccsid == 1047 ? "EBCDIC-1047" :
             ccsid == 819  ? "ISO-8859-1" : "binary/empty",
             is_text ? "on (text)" : (ccsid == 65535 ? "off (binary)" : "off"),
             size);
    tool_result(id, txt, 0);
}

static void handle_meta_read(const char *id, const char *args) {
    char path[4096] = {0};
    json_get_string(args, "path", path, sizeof(path));
    if (!path[0]) {
        send_error(id, -32602, "zscp_meta_read requires path");
        return;
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        char msg[4200];
        snprintf(msg, sizeof(msg), "cannot open %s: %s", path, strerror(errno));
        tool_result(id, msg, 1);
        return;
    }
    /* Cap at 64 KiB — meta files are small; truncate larger ones. */
    size_t cap = 65536;
    char *buf = malloc(cap + 1);
    if (!buf) { fclose(f); send_error(id, -32603, "out of memory"); return; }
    size_t n = fread(buf, 1, cap, f);
    int truncated = !feof(f);
    fclose(f);
    buf[n] = '\0';
    Buf txt; buf_init(&txt);
    buf_append(&txt, buf);
    if (truncated) buf_append(&txt, "\n... [truncated at 64 KiB]");
    free(buf);
    tool_result(id, txt.data, 0);
    buf_free(&txt);
}

static void handle_help(const char *id, const char *args) {
    (void)args;
    tool_result(id,
        "z-scp — pax-stream file transfer to/from z/OS with EBCDIC/tag handling.\n"
        "\n"
        "Usage: z-scp [options] <source> <destination>\n"
        "  upload:   z-scp localfile user@host:/remote/path\n"
        "  download: z-scp user@host:/remote/path localfile\n"
        "  recursive: add -r for directories.\n"
        "\n"
        "Options:\n"
        "  -r             recursive directory transfer\n"
        "  --dry-run      show what would be done without transferring\n"
        "  --verify       after upload, dump first 32 remote bytes via /bin/od\n"
        "  --ccsid N      force CCSID N for download conversion (e.g. 1047)\n"
        "  --smart        auto-detect encoding for untagged downloads\n"
        "  --meta         read/write .z-scp-meta.json alongside local files\n"
        "  --meta-file F  read/write meta data to/from file F\n"
        "  --reprobe      refresh cached PAX-header probe for the host\n"
        "\n"
        "Encoding/tagging:\n"
        "  Upload auto-detects EBCDIC-1047 / ISO-8859-1 / binary and tags via\n"
        "  ZOS.taginfo (no chtag step). With --meta, CCSID/tag/mode/mtime and\n"
        "  extattr+audit flags from the meta entry override auto-detection.\n"
        "  Download converts T=on IBM-1047 to local ISO-8859-1; T=off files\n"
        "  need --ccsid 1047 or --meta for faithful conversion.\n"
        "\n"
        "Via MCP use zscp_transfer(source, destination, ...) for transfers,\n"
        "zscp_detect(path) to classify a local file, zscp_meta_read(path)\n"
        "to inspect a meta sidecar.", 0);
}

static void handle_tools_call(const char *id, const char *req) {
    const char *args = find_arguments(req);
    char name[64] = {0};
    const char *params = strstr(req, "\"params\"");
    if (params) json_get_string(params, "name", name, sizeof(name));
    if (!name[0]) { send_error(id, -32602, "missing tool name"); return; }

    char empty[] = "{}";
    if (!args) args = empty;

    if (strcmp(name, "zscp_transfer") == 0)      handle_transfer(id, args);
    else if (strcmp(name, "zscp_detect") == 0)   handle_detect(id, args);
    else if (strcmp(name, "zscp_meta_read") == 0) handle_meta_read(id, args);
    else if (strcmp(name, "zscp_help") == 0)     handle_help(id, args);
    else {
        char msg[128];
        snprintf(msg, sizeof(msg), "unknown tool: %s", name);
        send_error(id, -32601, msg);
    }
}

/* -------------------------------------------------------------------------
 * Dispatch loop
 * ---------------------------------------------------------------------- */

static void dispatch(const char *line) {
    char method[128] = {0};
    char id[128] = {0};
    json_get_id(line, id, sizeof(id));
    json_get_string(line, "method", method, sizeof(method));

    int has_id = (strstr(line, "\"id\"") != NULL);
    if (!has_id) {
        /* Notification — acknowledge to stderr, never reply on stdout. */
        fprintf(stderr, SERVER_NAME ": notification: %s\n",
                method[0] ? method : "(none)");
        return;
    }

    if (strcmp(method, "initialize") == 0)      handle_initialize(id, line);
    else if (strcmp(method, "tools/list") == 0) handle_tools_list(id, line);
    else if (strcmp(method, "tools/call") == 0) handle_tools_call(id, line);
    else if (strcmp(method, "ping") == 0)       send_result(id, "{}");
    else {
        char msg[192];
        snprintf(msg, sizeof(msg), "method not found: %s",
                 method[0] ? method : "(none)");
        send_error(id, -32601, msg);
    }
}

int main(int argc, char **argv) {
    (void)argc;
    if (argv && argv[0]) g_argv0 = argv[0];
    setvbuf(stdout, NULL, _IONBF, 0);
    resolve_zscp();
    fprintf(stderr, SERVER_NAME " " SERVER_VERSION
                    " running on stdio (z-scp: %s)\n", g_zscp_path);

    char  *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, stdin)) > 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (line[0] == '\0') continue;
        dispatch(line);
    }
    free(line);
    fprintf(stderr, SERVER_NAME ": stdin closed, exiting\n");
    return 0;
}

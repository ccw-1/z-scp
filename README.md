# z-scp

A command-line tool for transferring files to and from **z/OS** over SSH, with
correct EBCDIC/ISO-8859-1 encoding handling, native z/OS file tagging, and
faithful round-trip preservation of z/OS-specific file attributes via a JSON
meta file.

Transfers are implemented as **pax archive streams** piped over `ssh` — no
dependency on `sftp`, `chtag`, `aepipe`, or any other local tool beyond `gcc`
and `ssh`.

---

## Features

- Single-file and recursive (`-r`) upload and download
- Automatic encoding detection (EBCDIC-1047 / ISO-8859-1 / binary)
- Native z/OS file tagging via `ZOS.taginfo` pax extended header — no
  separate `chtag` pass needed
- Preserves file mode bits and mtime across transfers
- **Meta file** (`--meta` / `--meta-file`): captures z/OS-specific per-file
  attributes on download and restores them faithfully on upload, including:
  - CCSID and tag state (T=on / T=off)
  - Extended attributes (`ZOS.extattr`: APF, program-controlled, shared-address-space)
  - Audit flags (`ZOS.useraudit`, `ZOS.auditoraudit`)
- AUTOCVT-aware: correctly handles z/OS SSH byte translation on both stdin
  and stdout
- `--smart` mode: auto-detects encoding for untagged (`T=off`) downloads
- `--ccsid N`: explicit CCSID override for downloads when you know the
  encoding
- Self-contained: single C file, no external libraries

---

## Requirements

- Linux / macOS (or any POSIX platform that is **not** z/OS)
- `gcc` (or any C11-compatible compiler)
- `ssh` with key-based auth configured for the z/OS host

---

## Build

```sh
make
# or directly:
gcc -std=c11 -Wall -Wextra -O2 -o z-scp z-scp.c
```

Install to `/usr/local/bin`:

```sh
make install
```

---

## Usage

```
z-scp [options] <source> <destination>
```

Direction is inferred from the arguments — use `user@host:/path` for the z/OS
side and a plain path for the local side:

```sh
# Upload a local file to z/OS
z-scp localfile.c   pok56:/home/user/localfile.c

# Download a file from z/OS
z-scp pok56:/home/user/output.log  ./output.log

# Recursive upload
z-scp -r ./myproject   pok56:/home/user/myproject

# Recursive download
z-scp -r pok56:/home/user/myproject  ./myproject
```

### Options

| Option | Description |
|---|---|
| `-r` | Recursive directory transfer |
| `--dry-run` | Show what would be done without transferring |
| `--verify` | After upload, dump first 32 remote bytes via `/bin/od` |
| `--smart` | Auto-detect encoding for untagged downloads (see below) |
| `--ccsid N` | Force CCSID N for download conversion (e.g. `1047`) |
| `--meta` | Read/write `.z-scp-meta.json` alongside the local files |
| `--meta-file F` | Read/write meta data to/from the explicit file `F` |

---

## Encoding and Tagging

### Upload

z-scp detects the encoding of each local file before upload:

| Detected encoding | Action |
|---|---|
| EBCDIC-1047 | Converted to ISO-8859-1 (CCSID 819) before transfer |
| ISO-8859-1 / binary | Transferred as-is |

Each file is tagged on z/OS automatically via the `ZOS.taginfo` pax extended
header — z/OS `pax -r` reads this and applies the correct tag on extraction,
with no additional `chtag` step.

When a meta file is present, the CCSID, tag state, mode, mtime, and extended
attributes from the meta entry override auto-detection for each file.

### Download

z/OS `pax -w` emits a `ZOS.taginfo` extended header for files tagged with
`T=on`. z-scp reads this and converts accordingly:

| Remote tag | Action |
|---|---|
| `T=on IBM-1047` | Bytes converted EBCDIC-1047 → ISO-8859-1 locally |
| `T=on IBM-819` | Written as-is |
| `T=on` other CCSID | Written as-is |
| `T=off` (any CCSID) | No `ZOS.taginfo` in pax stream — see below |
| Untagged | Written as-is |

### T=off files

When a file has `T=off`, its tag is recorded but not enforced — z/OS `pax -w`
does **not** emit `ZOS.taginfo` for it. z-scp has two options:

**`--smart`** — after downloading, runs encoding detection on the local file.
If every byte scores as valid EBCDIC-1047, the file is rewritten with EBCDIC →
ASCII conversion.

> **Note**: `--smart` uses a strict all-bytes test. The EBCDIC newline `0x15`
> is not in the valid set, so most EBCDIC text files will **not** be
> auto-converted. Use `--ccsid 1047` or a meta file for known EBCDIC files.

**`--ccsid 1047`** — forces EBCDIC → ASCII conversion regardless of what the
pax stream says.

```sh
# Download a T=off EBCDIC build log and convert it
z-scp --ccsid 1047  pok56:/home/user/._log  ./build.log
```

---

## Meta File

z/OS files carry attributes that have no portable equivalent and are silently
lost by ordinary file copy tools:

| Attribute | Pax carrier | Without `--meta` | With `--meta` |
|---|---|---|---|
| CCSID + T=on tag | `ZOS.taginfo` in `x` xhdr | ✅ preserved | ✅ preserved |
| T=off CCSID | Not emitted by `pax -w` | ❌ lost | ✅ captured & restored |
| Extended attributes (`extattr`) | `ZOS.extattr` in `g` xhdr | ✅ restored by `pax -r` | ✅ restored by `pax -r` |
| Audit flags (`useraudit`/`auditoraudit`) | `ZOS.useraudit` / `ZOS.auditoraudit` in `g` xhdr | ✅ restored by `pax -r` | ✅ restored by `pax -r` |

The meta file captures all of these on download so they can be restored
faithfully on a later upload.

### Format

```json
{
  "version": 1,
  "host": "pok56",
  "remote_root": "/u/ccw/myproject",
  "local_root": "myproject",
  "files": {
    "src/main.c": {
      "ccsid": 819,
      "tag": "on",
      "mode": "0644",
      "mtime": 1754500000
    },
    "src/convert.rexx": {
      "ccsid": 1047,
      "tag": "on",
      "mode": "0755",
      "mtime": 1754500100
    },
    "bin/myprog": {
      "ccsid": 65535,
      "tag": "off",
      "mode": "0755",
      "mtime": 1754500200,
      "extattr": "--s-"
    }
  }
}
```

#### Field reference

| Field | Values | Notes |
|---|---|---|
| `ccsid` | 819, 1047, 65535, 0 | 0 = unknown/untagged |
| `tag` | `"on"`, `"off"` | Reflects `T=on` / `T=off` on z/OS |
| `mode` | Octal string | Unix permission bits, e.g. `"0755"` |
| `mtime` | Unix timestamp | Seconds since epoch |
| `extattr` | 4-char string | `[apf][progctl][shareAS][-]`; omitted when `"----"` |
| `useraudit` | 3-char string | Omitted when default `"fff"` |
| `auditoraudit` | 3-char string | Omitted when default `"---"` |

#### `extattr` character positions

```
Position 0:  'a' = APF-authorized,         '-' = not
Position 1:  'p' = program-controlled,     '-' = not
Position 2:  's' = shared address space,   '-' = not
Position 3:  '-' (reserved)
```

### Usage

```sh
# Download a project and capture all z/OS attributes
z-scp -r pok56:/u/ccw/myproject ./myproject --meta
# → writes ./myproject/.z-scp-meta.json

# Upload it back, restoring all attributes faithfully
z-scp -r ./myproject pok56:/u/ccw/myproject --meta
# → reads ./myproject/.z-scp-meta.json

# Use an explicit meta file path
z-scp -r pok56:/u/ccw/myproject ./myproject --meta-file myproject.meta.json
z-scp -r ./myproject pok56:/u/ccw/myproject --meta-file myproject.meta.json

# Single-file download with meta
z-scp pok56:/u/ccw/bin/myprog ./myprog --meta
# → writes ./.z-scp-meta.json
```

### Upload behaviour with meta

For each file being uploaded:

1. **Meta entry found** — use `ccsid`, `tag`, `mode`, and `mtime` from the
   meta entry, overriding auto-detection entirely.
   - `ccsid=1047`: the local file (stored as ASCII after download conversion)
     is converted back to EBCDIC, and `ZOS.taginfo=1 1047` is set.
   - `tag="off"`: `ZOS.taginfo=0 <ccsid>` is emitted so z/OS `pax -r` sets
     T=off — preserving the original T=off state.
   - Non-default `extattr` / `useraudit` / `auditoraudit`: a `g` global xhdr
     is emitted immediately before that file's record; z/OS `pax -r` applies
     these attributes natively on extraction.

2. **No meta entry** (new file, or file added after the last download) —
   fall back to full auto-detection, identical to running without `--meta`.
   The file is content-scanned for CCSID, tagged T=on/binary, and uploaded
   with its current local mode and mtime. A `(auto-detect)` marker appears in
   the progress output so you can see which files had no recorded state.

3. The meta file itself is never uploaded to z/OS.

---

## How It Works

### AUTOCVT

z/OS SSH sessions run with `_BPXK_AUTOCVT=ON`, which transparently translates
bytes between EBCDIC and ASCII at the SSH boundary:

- **stdin (upload)**: z/OS applies `a2e[]` to bytes the remote process reads.
  z-scp pre-applies `e2a[]` so the net result is identity — z/OS `pax -r`
  sees the original bytes.
- **stdout (download)**: z/OS applies `e2a[]` to bytes the remote process
  writes. z-scp applies `a2e[]` on receipt to recover the original on-disk
  bytes.

### pax format

All transfers use the POSIX pax interchange format (`-x pax`). Per-file
tagging uses the `ZOS.taginfo` extended header:

```
21 ZOS.taginfo=1 819\n    ← text file, CCSID 819,   T=on
24 ZOS.taginfo=1 1047\n   ← EBCDIC text, CCSID 1047, T=on
23 ZOS.taginfo=0 819\n    ← text file, CCSID 819,   T=off
25 ZOS.taginfo=0 65535\n  ← binary,    CCSID 65535, T=off
```

Extended attributes and audit flags travel in the `g` (global) xhdr
immediately preceding each file's `x` + data record:

```
20 ZOS.extattr=--s-\n         ← shared-address-space set
21 ZOS.useraudit=fff\n        ← user audit flags
24 ZOS.auditoraudit=---\n     ← auditor audit flags
```

z/OS `pax -r` reads `ZOS.taginfo`, `ZOS.extattr`, `ZOS.useraudit`, and
`ZOS.auditoraudit` natively and applies them on extraction — no separate
`chtag` or `extattr` command needed.

---

## Limitations

- Remote-to-remote transfers are not supported.
- Only tested against z/OS OpenSSH with `_BPXK_AUTOCVT=ON`.
- `--smart` detection is unreliable for typical EBCDIC text files due to the
  `0x15` newline issue; use `--ccsid 1047` or a meta file for known EBCDIC
  files.
- APF authorization requires appropriate filesystem support and privileges; the
  `extattr` round-trip for `a` (APF) may silently fail if the target filesystem
  does not support it.

---

## License

MIT

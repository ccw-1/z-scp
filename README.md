# z-scp

A command-line tool for transferring files to and from **z/OS** over SSH, with
correct EBCDIC/ISO-8859-1 encoding handling and native z/OS file tagging.

Transfers are implemented as **pax archive streams** piped over `ssh` — no
dependency on `sftp`, `chtag`, `aepipe`, or any other local tool beyond `gcc`
and `ssh`.

---

## Features

- Single-file and recursive (`-r`) upload and download
- Automatic encoding detection (EBCDIC-1047 / ISO-8859-1 / binary)
- Native z/OS file tagging via `ZOS.taginfo` pax extended header — no
  separate `chtag` pass needed
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

### Download

z/OS `pax -w` emits a `ZOS.taginfo` extended header for files tagged with
`T=on`. z-scp reads this and converts accordingly:

| Remote tag | Action |
|---|---|
| `T=on IBM-1047` | Bytes converted EBCDIC-1047 → ISO-8859-1 |
| `T=on IBM-819` | Written as-is |
| `T=on` other CCSID | Written as-is |
| `T=off` (any CCSID) | No `ZOS.taginfo` in pax stream — see below |
| Untagged | Written as-is |

### T=off files

When a file has `T=off`, its tag is recorded but not enforced — z/OS `pax -w`
does **not** emit `ZOS.taginfo` for it. The bytes on disk may or may not match
the recorded CCSID. z-scp has two options for these files:

**`--smart`** — after downloading, runs encoding detection (the same logic as
[`tagfile`](https://github.com/ZOSOpenTools/utils)) on the local file. If
every byte scores as valid EBCDIC-1047, the file is rewritten with EBCDIC →
ASCII conversion.

> **Note**: `--smart` uses a strict all-bytes test. The EBCDIC newline `0x15`
> is not in the valid set, so most EBCDIC text files (which use `0x15` as a
> line terminator) will **not** be auto-converted. Use `--ccsid 1047` instead
> when you know the file is EBCDIC.

**`--ccsid 1047`** — forces EBCDIC → ASCII conversion regardless of what the
pax stream says. Use this when you know the file is EBCDIC (e.g. build logs
written by z/OS programs).

```sh
# Download a T=off EBCDIC build log and convert it
z-scp --ccsid 1047  pok56:/home/user/._log  ./build.log
```

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

All transfers use the POSIX pax interchange format (`-x pax`). Headers and
extended header data are plain ASCII throughout. Per-file tagging uses the
`ZOS.taginfo` extended header:

```
21 ZOS.taginfo=1 819\n    ← text file, CCSID 819
23 ZOS.taginfo=0 65535\n  ← binary file
```

The length field includes itself (POSIX pax requirement). z/OS `pax -r` reads
`ZOS.taginfo` natively.

---

## Limitations

- Remote-to-remote transfers are not supported.
- Only tested against z/OS OpenSSH with `_BPXK_AUTOCVT=ON`.
- `--smart` detection is unreliable for typical EBCDIC text files due to the
  `0x15` newline issue; use `--ccsid 1047` for known EBCDIC files.

---

## License

MIT

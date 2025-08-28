SYSTEM / ROLE
You are an expert Go developer and CLI architect. Generate production-quality, idiomatic Go (1.22+). Favor small, testable functions, clear comments, and streaming I/O. Use concurrency safely. The code must compile on Windows, Linux, and macOS.

GOAL
Create the foundational, modular collector framework for a DFIR tool named cryptkeeper. Include:

A Module interface and a Run orchestrator that executes modules concurrently with per-module timeouts.

A SysInfo module that writes host info (OS, arch, hostname, best-effort uptime) to JSON in a temporary artifacts directory.

A bundler that streams the temporary artifacts directory into a .tar.gz archive; if --encrypt-age is provided, stream the archive through age public-key encryption and save as .tar.gz.age.

Output a concise JSON summary of what was produced.

This MVP performs real collection only for the SysInfo module (low risk), plus packaging & optional encryption. No uploads yet.

Functional Requirements
1) CLI (minimal wiring for this MVP)

Binary name: cryptkeeper

Root command shows help if no subcommand.

Subcommand: cryptkeeper harvest

Flags (reused later as the project grows):

--since (string, optional; RFC3339 or duration like 7d, 72h, 2w), for future selective collection. For now, parse & normalize but it doesn’t affect SysInfo.

--parallel (int, default 4): max concurrent modules.

--module-timeout (duration, default 60s): per-module timeout.

--encrypt-age (string, optional): age public key (age1...). If set, bundling must encrypt the final archive via streaming.

--out (string, optional): directory to place the final archive; default: cwd.

--keep-tmp (bool, default false): keep the temporary artifacts directory after bundling for debugging.

On success, print a single compact JSON object to stdout describing the run (see “Output JSON” below). Errors → stderr, exit 1.

2) Module System

Define:

type Module interface {
Name() string
Collect(ctx context.Context, outDir string) error
}


Run orchestrator:

Holds: []Module, Parallelism int, ModuleTimeout time.Duration, ArtifactsDir string (temp dir), Clock (for testability), Logger.

Methods:

Register(m Module)

CollectAll(ctx context.Context) ([]Result, error)

Executes modules with a semaphore (Parallelism).

Each module gets its own context.WithTimeout(ctx, ModuleTimeout).

Each module writes files under ArtifactsDir/<sanitized module name>/....

Returns a slice of Result with {Module, StartedAt, EndedAt, Err}.

Errors: Non-fatal module errors should not abort other modules; aggregate and return combined error (first error + count, etc.).

3) SysInfo Module

Writes JSON to ArtifactsDir/sysinfo/sysinfo.json.

Include fields:

{
"os": "...",            // runtime.GOOS
"arch": "...",          // runtime.GOARCH
"hostname": "...",
"time_utc": "RFC3339",
"uptime_seconds": <int>,            // best-effort
"boot_time_utc": "RFC3339 or empty"
}


Uptime (best-effort):

Linux: read /proc/uptime (first float = seconds).

Windows: call GetTickCount64 via syscall/windows DLL (no admin required).

macOS: sysctl kern.boottime (use golang.org/x/sys/unix), compute now - boottime.

If any method fails, set uptime_seconds to 0 and boot_time_utc to "" and continue (no hard failure).

4) Bundling & Optional Encryption

Create a streaming packager:

Input: ArtifactsDir, OutDir, Hostname, Clock.Now(), AgePublicKey string.

Output file naming:

If not encrypted: cryptkeeper_<hostname>_<YYYYmmddTHHMMSSZ>.tar.gz

If encrypted: append .age → ...tar.gz.age

Implementation:

Open final file in OutDir.

Build writer pipeline:

If encrypt-age is set:

Parse recipient via filippo.io/age (age.ParseX25519Recipient(pubKey)).

encW, _ := age.Encrypt(fileW, recipient)

Wrap a gzip writer on top of encW: gz := gzip.NewWriter(encW).

tw := tar.NewWriter(gz).

Else: gz := gzip.NewWriter(fileW), tw := tar.NewWriter(gz).

Walk ArtifactsDir with filepath.WalkDir. For each file:

Compute a tar header with relative path artifacts/<subpath>.

Copy file contents to tw using io.Copy (no slurping into memory).

Close in correct order: tw.Close(), gz.Close(), encW.Close() (if used), file.Close().

Return final archive path and a small metadata struct (counts, bytes written, encrypted bool).

Do not armor the age output; binary .age is fine.

5) Output JSON (stdout on success)

Single-line JSON with (example keys—add others as needed):

{
"command": "harvest",
"artifacts_dir": "<temp path or kept path>",
"archive_path": "<final file path>",
"encrypted": true,
"age_recipient_set": true,
"parallelism": 4,
"module_timeout": "60s",
"modules_run": ["sysinfo"],
"module_results": [
{"name":"sysinfo","ok":true,"error":"","started_utc":"...","ended_utc":"..."}
],
"file_count": 1,
"bytes_written": 12345,
"timestamp_utc": "..."
}


If --keep-tmp=false, remove the temp dir after bundling. Still print its path for traceability (or "").

All errors go to stderr; exit 1.

Non-Functional Requirements

Code structure must be clean and extensible; keep CLI glue thin.

All filesystem writes must be under the temp ArtifactsDir.

Use streaming I/O (no reading whole files into memory).

Concurrency must respect context cancellation and timeouts.

Log minimal info to stderr (if needed); stdout is reserved for the JSON summary.

Allowed Dependencies

github.com/spf13/cobra (CLI)

filippo.io/age (encryption)

golang.org/x/sys/unix (Darwin uptime via sysctl)

Standard library for everything else (archive/tar, compress/gzip, etc.)

Project Layout (create real files with code)
.
├─ go.mod
├─ Makefile
├─ README.md
├─ cmd/
│  └─ cryptkeeper/
│     └─ main.go                 // calls internal/cli.Execute()
└─ internal/
├─ cli/
│  ├─ root.go                 // root cmd
│  └─ harvest.go              // parse flags → build core.Run → execute
├─ core/
│  ├─ run.go                  // Run, Module, Result, orchestrator
│  ├─ pack.go                 // BundleAndMaybeEncrypt(...)
│  └─ util.go                 // helpers (sanitize names, tempdir, clock)
├─ modules/
│  ├─ sysinfo/
│  │  ├─ sysinfo.go           // module shell (OS-agnostic)
│  │  ├─ sysinfo_linux.go     // +build linux: uptime via /proc/uptime
│  │  ├─ sysinfo_windows.go   // +build windows: uptime via GetTickCount64
│  │  └─ sysinfo_darwin.go    // +build darwin: uptime via sysctl
└─ schema/
└─ run_output.go           // JSON output structs

Implementation Details
CLI Flags (harvest)

--parallel default 4; clamp to [1..64].

--module-timeout parse via time.ParseDuration, default 60s (error on invalid).

--encrypt-age optional; validate:

If set, must start with age1 and age.ParseX25519Recipient() must succeed.

--out default . (cwd); ensure directory exists and writable.

--since parse + normalize to RFC3339 if set (duration or RFC3339). Keep for future modules; store in the JSON output.

Run Orchestration

Create temp artifacts dir with os.MkdirTemp("", "cryptkeeper_*").

Register only SysInfo for this MVP.

Concurrency: buffered channel as semaphore.

For each module:

ctx, cancel := context.WithTimeout(parent, ModuleTimeout)

Per-module subfolder: ArtifactsDir/sanitized(module.Name()).

Collect errors, timestamps.

After modules finish, call BundleAndMaybeEncrypt(ctx, ArtifactsDir, OutDir, hostname, nowUTC, encryptAgeKey).

SysInfo Module

OS-agnostic shell calls a getUptime() implemented per-OS via build tags.

Always fill os, arch, hostname, time_utc.

uptime_seconds and boot_time_utc may be zero/empty if not available.

Write pretty (or compact) JSON to sysinfo.json.

Bundling

Use archive/tar + compress/gzip.

Add files with relative paths under artifacts/.

Count files and bytes while writing.

If encryptAgeKey != "":

recipient, err := age.ParseX25519Recipient(key)

encW, err := age.Encrypt(fileW, recipient)

Wrap gzip around encW.

Close writers in reverse order; handle errors carefully.

Output JSON

Build a struct with all fields described; marshal with encoding/json (no pretty-print) and print to stdout.

Tests (table-driven where possible)

core/run.go: unit test with a fake fast module + slow module, verifying timeout cancels slow one and both results recorded.

modules/sysinfo: test JSON structure integrity (mock uptime to deterministic value).

core/pack.go: create a temp dir with a few small files; ensure tar.gz is produced; with a dummy age key, ensure .age file is produced and size > 0 (no need to decrypt in test).

Basic CLI test via go test invoking command constructors (no exec).

Makefile

build: go build -o bin/cryptkeeper ./cmd/cryptkeeper

test: go test ./...

lint: go vet ./...

README.md (include usage examples)

Examples (timestamps illustrative):

# Basic run, encrypted output
cryptkeeper harvest --parallel 4 --module-timeout 60s \
--encrypt-age age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq \
--out ./out
# → prints JSON summary with archive_path ending in .tar.gz.age

# Unencrypted output (development only)
cryptkeeper harvest --parallel 2 --module-timeout 30s --out ./out
# → prints JSON with archive_path ending in .tar.gz

# Keep artifacts dir for inspection
cryptkeeper harvest --keep-tmp --out ./out

Deliverables

All files per the structure above, with compilable code.

Working SysInfo module, runner, and bundler.

Optional encryption fully implemented via streaming with age.

Clean, single-line JSON summary on stdout; meaningful errors on stderr.

Now generate the complete project (all files) in a single response.
SYSTEM / ROLE
You are an expert Go developer on Windows internals and DFIR tooling. Produce production-quality, idiomatic Go (1.22+). Prefer small, testable functions. Handle Windows specifics carefully (privileges, locked files, path quoting). Minimize external deps; use the standard library and golang.org/x/sys/windows when necessary.

GOAL
Add a Windows-only module WinEvtx to cryptkeeper that exports/copies key Event Logs into the collector’s artifacts folder and computes SHA-256 hashes. The module must gracefully no-op on non-Windows. This module prepares data that the existing bundler will later package and (optionally) encrypt before upload; do not implement encryption or uploads here.

Functional Requirements
Module contract & registration

Implement a module that satisfies:

type Module interface {
Name() string
Collect(ctx context.Context, outDir string) error
}


Name() returns "windows/evtx".

Register this module from the place where other modules are registered (e.g., internal/cli/harvest.go or internal/core/run.go).

Platforms

Provide Windows build implementation in internal/modules/win_evtx/win_evtx_windows.go (//go:build windows).

Provide a non-Windows stub in internal/modules/win_evtx/win_evtx_other.go (//go:build !windows) whose Collect returns nil.

What to collect (Windows)

Export these channels to .evtx files under:

<ArtifactsDir>/windows/evtx/
Security.evtx
System.evtx
Microsoft-Windows-PowerShell%4Operational.evtx


Channels:

Security

System

Microsoft-Windows-PowerShell/Operational

Compute SHA-256 for each exported file and write a manifest:

<ArtifactsDir>/windows/evtx/manifest.json


Example content:

{
"channel_files": [
{"channel":"Security","file":"Security.evtx","size":123456,"sha256":"..."},
{"channel":"System","file":"System.evtx","size":78910,"sha256":"..."},
{"channel":"Microsoft-Windows-PowerShell/Operational","file":"Microsoft-Windows-PowerShell%4Operational.evtx","size":1112,"sha256":"..."}
],
"created_utc":"2025-08-26T21:00:00Z",
"host":"HOSTNAME",
"cryptkeeper_version":"v0.1.0"
}

Export method & locking

Primary method (preferred): use the built-in Windows exporter wevtutil.exe epl to export each channel to a destination file. This avoids “file in use” issues.

Command form:

wevtutil epl <ChannelName> <OutputPath> /ow:true


If --since was provided to the CLI and normalized to RFC3339, apply a time filter using an XML query via /q: with timediff(@SystemTime) <= <ms>:

Compute milliseconds between now (UTC) and the since timestamp.

Example arg:

/q:*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]


Use exec.CommandContext(ctx, "wevtutil", args...) with proper quoting/arguments array (no shell concatenation).

Fallback method (best-effort): if wevtutil epl fails for a channel (e.g., insufficient privilege), attempt a direct file copy of:

%SystemRoot%\System32\winevt\Logs\<ChannelFile>.evtx


where:

Security → Security.evtx

System → System.evtx

Microsoft-Windows-PowerShell/Operational → Microsoft-Windows-PowerShell%4Operational.evtx

Use windows.CreateFile with generous share flags (FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE) and CopyFileEx/streamed io.Copy to tolerate locks.

If both export and copy fail, record an error for that channel but continue with others.

Privileges & errors

Access to Security usually requires elevation (Administrator/Event Log Readers). Detect elevation (token inspection) and include a helpful error if export fails due to access denied.

Do not fail the whole module if one channel fails. Collect what you can, and return a combined error describing which channels failed.

Hashing

Compute SHA-256 streaming (no slurping into memory). Return hex string.

Include size (bytes) from os.Stat.

Respect orchestrator context & timeouts

All channel exports must respect the context passed to Collect. If the context is done, stop child processes (kill wevtutil) and return.

Since-time handling

Accept a normalized RFC3339 since value from the CLI layer if available (you may read it from a shared config object or from the environment the CLI set up).

If unset, export the entire channel (wevtutil epl <Channel> <Out> with no /q:).

If set, build the milliseconds window for timediff(@SystemTime) <= <ms>. Clamp at zero if the computed window is negative.

Output & logging

Write exported .evtx files and manifest.json into the module folder.

Any module diagnostics should go to stderr via the project’s logger (if available) or minimal log.Printf, but keep stdout clean for the final run JSON summary printed by the CLI.

Return a clear error summarizing failed channels (e.g., "WinEvtx: failed for channels: Security (access denied), PowerShell/Operational (timeout)").

Non-Functional Requirements

Clean, testable code. Split helpers: building export args, running wevtutil, copying raw file, hashing, manifest writing, admin detection.

No panics. Handle Windows API and syscall errors with context.

No network or encryption here; just local export and hashing.

Allowed Dependencies

Standard library

golang.org/x/sys/windows (for privilege checks and file open flags)

Project Layout (add these new files)
internal/
modules/
win_evtx/
win_evtx_windows.go   // real implementation (//go:build windows)
win_evtx_other.go     // stub (//go:build !windows)
manifest.go           // types + manifest writer
hash.go               // streaming SHA-256 helper
admin_windows.go      // isAdmin() token/elevation check
copy_windows.go       // tolerant copy helpers with share flags

Implementation Details
1) Channel constants & mapping

Maintain a map:

var channels = []struct{
Channel string
File    string
}{
{"Security", "Security.evtx"},
{"System", "System.evtx"},
{"Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell%4Operational.evtx"},
}


Also keep a map for raw log file paths under %SystemRoot%\System32\winevt\Logs\<File> for fallback.

2) wevtutil epl execution

Build args:

base: []string{"epl", channel, destPath, "/ow:true"}

if sinceMs > 0: append "/q:*[System[TimeCreated[timediff(@SystemTime) <= <ms>]]]" (ensure it’s one arg; wrap the whole XPath in quotes).

Use exec.CommandContext(ctx, "wevtutil", args...). Capture stderr for error messages. Check cmd.Run() error + context deadline.

3) Fallback copy (locked file tolerant)

If wevtutil fails:

Open source with windows.CreateFile:

Desired access: GENERIC_READ

Share mode: FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

Creation disp: OPEN_EXISTING

Flags: FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS

Wrap handle with os.NewFile and stream copy to destination using io.Copy.

Close handles in defer. Return wrapped errors.

4) Hashing + manifest

After each file is produced, compute SHA-256:

Use a sha256.New() and stream the file through it.

Accumulate entries in a slice and write manifest.json (compact) at the end.

5) Admin detection (helpful messaging)

Implement isAdmin():

Use token query (elevated/elevation type) or windows.IsUserAnAdmin equivalent pattern (group SID for Administrators).

If not admin and Security export fails with access denied, add guidance to the error: “Run elevated or add user to Event Log Readers.”

6) Context & timeouts

Ensure per-channel export respects context; if ctx.Done(), kill wevtutil.

Propagate first error per channel; aggregate at module exit.

Tests

//go:build windows tests that:

Build arguments for wevtutil correctly (channel name, /ow:true, optional /q:).

Hashing function returns expected hex for known content.

Manifest writer outputs expected JSON (stable ordering not required; compare decoded structs).

//go:build !windows test that the stub returns nil.

(You don’t need to integration-test wevtutil execution.)

Example Behavior (illustrative)

On Windows, elevated, with --since 7d: exports the three channels with a time filter, writes .evtx files + manifest.json.

On Windows, non-elevated: System and PowerShell/Operational may succeed; Security likely fails → record error for Security but module overall returns error summarizing failures (or, per your orchestrator, “partial success”).

On Linux/macOS: module registers but Collect is a no-op and returns nil.

Deliverables

Implement all files as described.

Clean build across platforms (go build ./...), with functionality active only on Windows.

The module’s output lands under ArtifactsDir/windows/evtx/ so the existing bundler will package it and (if configured) encrypt the archive later.

Now generate the complete implementation (all new files) in a single response.
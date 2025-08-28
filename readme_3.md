SYSTEM / ROLE

You are an expert Go developer with deep Windows DFIR knowledge. Generate production-quality, idiomatic Go (1.22+). Favor small, testable functions, streaming I/O, and safe concurrency. Handle Windows paths, permissions, and locked files carefully. The code must compile cross-platform, with Windows-only implementations guarded by build tags.

GOAL

Extend cryptkeeper with Windows artifact collection. Create a set of Windows modules that collect critical forensic artifacts by copying/exporting files into the run’s artifacts directory. Compute SHA-256 for each captured file and write a manifest.json per module. Modules no-op on non-Windows. Bundling + (optional) age encryption is already implemented elsewhere—just ensure outputs land under the module’s folder so the bundler picks them up.

ARCHITECTURE REQUIREMENTS
Module contract (already exists)
type Module interface {
Name() string
Collect(ctx context.Context, outDir string) error
}

New modules to implement (Windows only)

Create a folder per module under internal/modules/ with a Windows implementation (//go:build windows) and a stub for other OSes (//go:build !windows) that returns nil. Each module:

Writes to <ArtifactsDir>/<module-specific-subpath>/...

Streams copies/exports (no whole-file slurp).

Computes SHA-256 per file.

Writes a compact manifest.json capturing file list, sizes, hashes, timestamps, hostname, module version.

Respects context/timeouts; graceful partial success (collect what you can, aggregate errors).

Avoids stdout (reserved for final run JSON). Minimal stderr logging if needed.

Register the modules alongside SysInfo so they run under cryptkeeper harvest.

PRIVILEGE & LOCKING STRATEGY

Attempt to enable SeBackupPrivilege and SeRestorePrivilege at module start (Windows only). Fall back gracefully if not granted.

Prefer exporters (e.g., wevtutil epl) to avoid locked file issues.

For direct file copies from protected locations, open with generous share flags:

FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

GENERIC_READ, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS.

If a primary method fails, attempt a fallback (documented below). If still failing, record the error and continue.

Provide a shared helper package internal/winutil/ with:

EnableBackupRestorePrivileges() error

OpenForCopy(path string) (*os.File, error) using proper Win APIs.

CopyFileStreaming(src *os.File, dstPath string) (bytes int64, sha256Hex string, err error)

ExportEventLog(ctx context.Context, channel string, destPath string, sinceRFC3339 string) error (wraps wevtutil epl + optional /q:).

“SINCE” FILTERING (IF PROVIDED)

If the CLI provided a normalized RFC3339 since time, apply it where sensible:

Event Logs: wevtutil epl with /q:*[System[TimeCreated[timediff(@SystemTime) <= ms]]] (ms = nowUTC - since).

Journaled/rolling logs (e.g., Defender): prefer channel export with query; if copying flat files, ignore filter.

If since isn’t set, collect full artifacts (subject to size caps).

SIZE & SCOPE GUARDRAILS

Per module defaults:

maxFileSizeMB: 512 (configurable constant)

maxTotalMB: 2048 (configurable constant)

If a file exceeds cap, copy a truncated tail with -partN suffix and record truncated: true in the manifest.

Respect process context cancellation promptly.

MODULE SET & TARGETS (INITIAL PASS)

Use environment variables like %SystemRoot%, %SystemDrive%, %ProgramData%, %ALLUSERSPROFILE%, %USERPROFILE%, and expand per-user paths by enumerating C:\Users\<SID or name> (skip well-known service profiles). All module outputs go under artifacts/windows/<module>/....

1) WinEvtx (Event Logs) — already spec’d, include here for completeness

Channels (at minimum):

Security, System, Application

Microsoft-Windows-PowerShell/Operational

Microsoft-Windows-TaskScheduler/Operational

Microsoft-Windows-TerminalServices-LocalSessionManager/Operational

Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational

If present: Microsoft-Windows-Sysmon/Operational, Microsoft-Windows-Windows Defender/Operational, Microsoft-Windows-DNS-Client/Operational

Use wevtutil epl with optional /q: since filter. Fallback: copy from %SystemRoot%\System32\winevt\Logs\*.evtx.

2) WinRegistryHives

Copy these system hives from %SystemRoot%\System32\config\:

SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT

Per-user hives:

C:\Users\<User>\NTUSER.DAT

C:\Users\<User>\AppData\Local\Microsoft\Windows\UsrClass.dat

Prefer direct copy with backup semantics. Fallback: reg.exe save HKLM\SYSTEM <dest> etc. Record which method used.

3) WinPrefetch

C:\Windows\Prefetch\*.pf (if EnablePrefetcher is on; may be absent on servers).

Capture all .pf within caps; compute hashes.

4) WinAmcache

C:\Windows\AppCompat\Programs\Amcache.hve

Also include RecentFileCache.bcf if present (older OS).

5) WinShimcache (AppCompatCache Snapshot)

Capture SYSTEM hive already; in manifest note that shimcache is contained in SYSTEM hive path: ControlSet00x\Control\Session Manager\AppCompatCache.

Optionally dump a parsed JSON alongside (best-effort), but raw hive copy is sufficient for MVP. If parsing, do it in a separate helper file.

6) WinJumpLists

Per user:

%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms

%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms

7) WinLNK

Per user shortcuts:

%APPDATA%\Microsoft\Windows\Recent\*.lnk

Desktop / Start Menu shortcuts (optional): gather with caps.

8) WinSRUM

C:\Windows\System32\sru\SRUDB.dat (+ *.dat logs in folder)

Copy ESE database files; do not attempt parsing here.

9) WinBITS

C:\ProgramData\Microsoft\Network\Downloader\qmgr*.dat

10) WinScheduledTasks

C:\Windows\System32\Tasks\** (XML files). Preserve directory structure.

11) WinServicesDrivers

Registry coverage already (SYSTEM hive). Also:

List files under C:\Windows\System32\drivers\*.sys (with caps).

Optional: driverquery /v /fo csv captured to a text file.

12) WinWMI

C:\Windows\System32\wbem\Repository\** (e.g., OBJECTS.DATA)

Optional: export WMI permanent event subscriptions via PowerShell to a JSON report.

13) WinFirewallAndNetwork

Windows Firewall log (if enabled):

%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

ipconfig /all and route print output saved as text files (best-effort, keep small).

14) WinRDPArtifacts

RDP bitmap cache (per user):

%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\*

Default.rdp in user profile root if present.

15) WinUSBAndDeviceInstall

SYSTEM hive keys:

Enum\USBSTOR

MountedDevices

C:\Windows\inf\setupapi.dev.log

16) WinBrowserArtifacts (Chromium + Firefox) (bounded)

Chromium (Chrome/Edge/Brave) per user (cap sizes):

%LOCALAPPDATA%\Google\Chrome\User Data\**\History

%LOCALAPPDATA%\Microsoft\Edge\User Data\**\History

Associated SQLite DBs: History, Login Data, Cookies (size-cap; copy raw).

Firefox:

%APPDATA%\Mozilla\Firefox\Profiles\**\places.sqlite, cookies.sqlite

17) WinRecycleBin

For each drive: \$Recycle.Bin\<SID>\*
Copy $I and $R pairs (respect caps). Don’t attempt parsing.

18) WinIIS (if role installed)

%SystemDrive%\inetpub\logs\LogFiles\W3SVC* (cap per file, e.g., tail 50MB).

Feel free to add Defender supplementary logs (e.g., C:\ProgramData\Microsoft\Windows Defender\Support\*) within caps.

IMPLEMENTATION DETAILS
File hashing & manifest

Reuse a shared helper for streaming SHA-256 while copying.

Manifest structure per module:

{
"created_utc": "RFC3339",
"host": "HOSTNAME",
"cryptkeeper_version": "v0.1.0",
"items": [
{"path":"<relative>", "size":1234, "sha256":"...", "truncated":false, "note":"<optional>"},
...
],
"errors": [
{"target":"<what failed>", "error":"<message>"}
]
}

Per-user enumeration

Enumerate C:\Users\*; skip:

All Users, Default, Default User, Public, WDAGUtilityAccount, system profiles.

Derive SID for manifest if convenient (optional).

Helpers to write (shared across modules)

func EnsureDir(path string) error

func SafeRel(base, path string) (string, error) (guard tar traversal later)

func TailCopy(src *os.File, maxBytes int64, dstPath string) for large logs (record truncated: true)

Context & timeouts

For process invocations (wevtutil, driverquery, ipconfig): use exec.CommandContext.

Kill processes on context cancel.

PROJECT LAYOUT (additions)
internal/
modules/
win_evtx/           (as specified earlier)
win_registry/
win_registry_windows.go
win_registry_other.go
manifest.go
win_prefetch/
...
win_amcache/
...
win_jumplists/
...
win_lnk/
...
win_srum/
...
win_bits/
...
win_tasks/
...
win_services_drivers/
...
win_wmi/
...
win_firewall_net/
...
win_rdp/
...
win_usb/
...
win_browser/
...
win_recyclebin/
...
win_iis/
...
winutil/
privileges_windows.go     // enable SeBackup/SeRestore
filecopy_windows.go       // OpenForCopy, CopyFileStreaming
process_windows.go        // Exec helpers with ctx, capture stderr
sizecaps.go               // tail copy helpers


Each module has a Windows implementation and a non-Windows stub that returns nil.

TESTS

Unit tests for hash/manifest helpers (OS-agnostic).

Build-tagged tests on Windows:

Argument builders (e.g., wevtutil query with ms).

File copy with hash on a small temp file.

Size-cap tail behavior.

Non-Windows test ensures stubs return nil and don’t create outputs.

OUTPUT INTEGRATION

Ensure all modules write under artifacts/windows/<module>/... so the bundler picks them up.

The final cryptkeeper harvest JSON summary should include these module names in modules_run and reflect per-module success/partial errors as already defined in the orchestrator.

DELIVERABLES

Implement the modules listed above (at least stubs for all; full implementations for WinRegistryHives, WinPrefetch, WinAmcache, WinJumpLists, WinLNK, WinSRUM, WinBITS, and the already-specified WinEvtx).

Shared helpers in internal/winutil/ as described.

Clean build on all platforms (go build ./...), with Windows logic behind build tags.

No uploads or encryption here; bundling/encryption runs after modules complete.

EXAMPLES (behavior, illustrative)

Elevated run with --since 7d: WinEvtx exports recent logs with query; registry/system hives copied via backup privilege; per-user artifacts copied respecting caps; manifests summarize files + hashes.

Non-elevated run: some protected files fail (SAM/SECURITY, Security.evtx export). These are recorded in manifest errors, module continues; overall run still succeeds with partials.

Non-Windows host: modules no-op, return nil; only non-Windows modules (if any) run.

Now generate all new module packages, stubs, helpers, and unit tests per the above.
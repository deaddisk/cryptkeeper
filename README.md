# cryptkeeper

A comprehensive DFIR (Digital Forensics and Incident Response) CLI tool for collecting Windows system artifacts and packaging them securely. Designed for forensic analysts and incident responders who need to rapidly collect critical artifacts from Windows systems.

## Installation

### Prerequisites

- Go 1.22+ installed
- Git (for cloning the repository)

### Building for Windows (Primary Target)

Cryptkeeper is optimized for Windows systems. Here are multiple ways to build Windows binaries:

#### Option 1: Build on Windows

```cmd
REM Download dependencies
go mod tidy

REM Build for Windows (current architecture)
go build -o bin/cryptkeeper.exe ./cmd/cryptkeeper

REM Build for Windows 64-bit specifically
set GOOS=windows
set GOARCH=amd64
go build -o bin/cryptkeeper-x64.exe ./cmd/cryptkeeper

REM Build for Windows 32-bit
set GOOS=windows
set GOARCH=386
go build -o bin/cryptkeeper-x86.exe ./cmd/cryptkeeper
```

#### Option 2: Cross-compile from Linux/macOS

```bash
# Download dependencies
go mod tidy

# Build Windows 64-bit binary from Linux/macOS
GOOS=windows GOARCH=amd64 go build -o bin/cryptkeeper-x64.exe ./cmd/cryptkeeper

# Build Windows 32-bit binary from Linux/macOS
GOOS=windows GOARCH=386 go build -o bin/cryptkeeper-x86.exe ./cmd/cryptkeeper

# Build Windows ARM64 binary (for newer ARM-based Windows systems)
GOOS=windows GOARCH=arm64 go build -o bin/cryptkeeper-arm64.exe ./cmd/cryptkeeper
```

#### Option 3: Using Make (if available)

```bash
# Default build (creates Windows binary regardless of host platform)
make build

# Build all Windows architectures
make build-all-windows

# Build for specific architecture
make build-windows-x64
make build-windows-x86
make build-windows-arm64
```

#### Option 4: Build Native Binary (for testing on non-Windows)

```bash
# Build native binary for current platform (Linux/macOS)
# Note: Only SysInfo module will work on non-Windows systems
go build -o bin/cryptkeeper ./cmd/cryptkeeper
```

### Build Output

The build process creates binaries in the `bin/` directory:

- `cryptkeeper.exe` - Main Windows executable (64-bit by default)
- `cryptkeeper-x64.exe` - Windows 64-bit executable
- `cryptkeeper-x86.exe` - Windows 32-bit executable  
- `cryptkeeper-arm64.exe` - Windows ARM64 executable
- `cryptkeeper` - Native binary for Linux/macOS (limited functionality)

### Deployment to Windows Systems

Once built, the binary can be deployed to Windows systems for artifact collection:

```cmd
REM Copy to target Windows system
copy cryptkeeper.exe \\target-system\C$\temp\

REM Run remotely via admin share
psexec \\target-system C:\temp\cryptkeeper.exe harvest --encrypt-age YOUR_AGE_KEY

REM Or copy via RDP/WinRM and run locally
cryptkeeper.exe harvest --parallel 8 --out C:\collection
```

**Requirements on target system:**
- No additional dependencies (statically linked Go binary)
- Works on Windows 7, 8, 10, 11, Server 2008+
- Elevated privileges recommended for full artifact access

## Usage

After building, run the binary from the bin directory or add it to your PATH.

### Root Command

```cmd
REM From the bin directory
cd bin
cryptkeeper.exe

REM Or with full path
bin\cryptkeeper.exe
```

Shows help and available subcommands.

### Harvest Command

The `harvest` command runs collection modules to gather system artifacts, packages them into a compressed archive, and optionally encrypts the result using age public key encryption.

```cmd
cd bin
cryptkeeper.exe harvest [flags]
```

#### Flags

- `--since`: RFC3339 timestamp or duration like 7d, 72h, 15m, 30s, 2w (optional, for future use)
- `--parallel`: Maximum concurrent modules, 1-64 (default: 4)
- `--module-timeout`: Per-module timeout duration (default: 60s)
- `--encrypt-age`: Age public key for encryption (must start with age1)
- `--out`: Output directory for final archive (default: temporary directory)
- `--keep-tmp`: Keep temporary artifacts directory for debugging (default: false)

## Examples

### Basic unencrypted collection

```cmd
cd bin
cryptkeeper.exe harvest --parallel 2 --module-timeout 30s
```

Output JSON:
```json
{
  "command": "harvest",
  "artifacts_dir": "",
  "archive_path": "C:\\Users\\Username\\AppData\\Local\\Temp\\cryptkeeper_123456\\cryptkeeper_hostname_20250827T123456Z.tar.gz",
  "encrypted": false,
  "age_recipient_set": false,
  "parallelism": 2,
  "module_timeout": "30s",
  "modules_run": ["sysinfo", "windows/evtx", "windows/registry", "windows/prefetch", "windows/amcache", "windows/jumplists", "windows/lnk", "windows/srum", "windows/bits", "windows/tasks", "windows/services_drivers", "windows/wmi", "windows/firewall_net", "windows/rdp", "windows/usb", "windows/browser", "windows/recyclebin", "windows/iis", "windows/networkinfo", "windows/systemconfig", "windows/memory_process", "windows/applications", "windows/persistence", "windows/modern", "windows/mft", "windows/usn", "windows/vss", "windows/fileshares", "windows/lsa", "windows/kerberos", "windows/logon", "windows/tokens", "windows/ads", "windows/signatures", "windows/certificates", "windows/trustedinstaller"],
  "module_results": [
    {
      "name": "sysinfo",
      "ok": true,
      "error": "",
      "started_utc": "2025-08-27T12:34:56Z",
      "ended_utc": "2025-08-27T12:34:56Z"
    }
  ],
  "file_count": 1,
  "bytes_written": 2048,
  "timestamp_utc": "2025-08-27T12:34:56Z"
}
```

### Encrypted collection with age

```cmd
cd bin
cryptkeeper.exe harvest --parallel 4 --module-timeout 60s --encrypt-age age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
```

Output JSON:
```json
{
  "command": "harvest",
  "artifacts_dir": "",
  "archive_path": "C:\\Users\\Username\\AppData\\Local\\Temp\\cryptkeeper_789012\\cryptkeeper_hostname_20250827T123456Z.tar.gz.age",
  "encrypted": true,
  "age_recipient_set": true,
  "parallelism": 4,
  "module_timeout": "1m0s",
  "modules_run": ["sysinfo", "windows/evtx", "windows/registry", "windows/prefetch", "windows/amcache", "windows/jumplists", "windows/lnk", "windows/srum", "windows/bits", "windows/tasks", "windows/services_drivers", "windows/wmi", "windows/firewall_net", "windows/rdp", "windows/usb", "windows/browser", "windows/recyclebin", "windows/iis", "windows/networkinfo", "windows/systemconfig", "windows/memory_process", "windows/applications", "windows/persistence", "windows/modern", "windows/mft", "windows/usn", "windows/vss", "windows/fileshares", "windows/lsa", "windows/kerberos", "windows/logon", "windows/tokens", "windows/ads", "windows/signatures", "windows/certificates", "windows/trustedinstaller"],
  "module_results": [
    {
      "name": "sysinfo",
      "ok": true,
      "error": "",
      "started_utc": "2025-08-27T12:34:56Z",
      "ended_utc": "2025-08-27T12:34:56Z"
    }
  ],
  "file_count": 1,
  "bytes_written": 2156,
  "timestamp_utc": "2025-08-27T12:34:56Z"
}
```

### Keep temporary artifacts for debugging

```cmd
cd bin
cryptkeeper.exe harvest --keep-tmp
```

This keeps the temporary artifacts directory and shows its path in the output JSON.

### Error cases

```cmd
cd bin

REM Invalid age key
cryptkeeper.exe harvest --encrypt-age invalidkey
REM Error: invalid --encrypt-age: age public key must start with 'age1'

REM Invalid parallelism (automatically clamped)
cryptkeeper.exe harvest --parallel 100
REM Uses maximum of 64 instead

REM Invalid module timeout
cryptkeeper.exe harvest --module-timeout -5s
REM Error: module-timeout must be positive
```

## Collected Artifacts

Cryptkeeper comprehensively collects critical Windows DFIR artifacts across 35+ specialized modules organized into 9 categories:

### Core System Information
- **SysInfo**: Basic system information (OS, arch, hostname, uptime, boot time)

### Windows Event Logs & Registry
- **WinEvtx**: Windows Event Logs (Security, System, Application, PowerShell, TaskScheduler, RDP, Sysmon, Defender, DNS)
- **WinRegistry**: System registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT) and per-user hives (NTUSER.DAT, UsrClass.dat)

### Execution Artifacts
- **WinPrefetch**: Windows Prefetch files (*.pf) for application execution tracking
- **WinAmcache**: Application Compatibility cache (Amcache.hve, RecentFileCache.bcf)
- **WinTasks**: Scheduled Tasks (XML files from C:\Windows\System32\Tasks)

### File System & User Activity
- **WinJumpLists**: Jump Lists (AutomaticDestinations, CustomDestinations)  
- **WinLNK**: LNK shortcut files from Recent items and Desktop
- **WinSRUM**: System Resource Usage Monitor database (SRUDB.dat)
- **WinRecycleBin**: Recycle Bin artifacts ($I and $R files) from all drives

### Network & External Devices  
- **WinFirewallNet**: Windows Firewall logs, network configuration (ipconfig, route table)
- **WinUSB**: USB device installation logs (setupapi.dev.log)
- **WinRDP**: RDP bitmap cache and configuration files per user profile
- **WinNetworkInfo**: Comprehensive network configuration (DNS cache, ARP table, netstat, SMB shares)

### Applications & Services
- **WinBrowser**: Browser artifacts (Chrome, Edge, Firefox history, cookies, login data)
- **WinBITS**: Background Intelligent Transfer Service job queue files (qmgr*.dat)
- **WinServicesDrivers**: System drivers (*.sys files) and driver information (driverquery output)
- **WinWMI**: WMI repository files and permanent event subscriptions
- **WinIIS**: IIS web server logs (when installed)
- **WinApplications**: Application-specific artifacts (Office recent files, Skype databases, Teams configs, Outlook metadata, Windows Defender logs)

### System Configuration & Memory
- **WinSystemConfig**: System configuration (services, startup programs, environment variables, timezone, hosts file)
- **WinMemoryProcess**: Memory and process artifacts (detailed process info, handles, memory info, virtual memory metadata)

### Persistence & Malware Hunting
- **WinPersistence**: Persistence mechanisms (autorun locations, thumbnail cache, icon cache, ShellBags info, COM objects)
- **WinModern**: Cloud & modern Windows artifacts (OneDrive logs/settings, Cortana data, Timeline database, clipboard history, Store apps)

### File System Deep Analysis
- **WinMFT**: NTFS Master File Table metadata and volume information
- **WinUSN**: NTFS USN Journal information and change tracking
- **WinVSS**: Volume Shadow Copy Service information and metadata
- **WinFileShares**: File shares configuration, permissions, and active sessions

### Authentication & Security
- **WinLSA**: LSA policy information and security settings
- **WinKerberos**: Kerberos tickets and authentication configuration
- **WinLogon**: Logon sessions and authentication history
- **WinTokens**: Access tokens and privileges information

### Forensic Metadata
- **WinADS**: Alternate Data Streams detection and analysis
- **WinSignatures**: File signatures and digital certificate verification
- **WinCertificates**: Certificate stores and PKI configuration
- **WinTrustedInstaller**: TrustedInstaller service and system integrity information

### Collection Features
- **Smart Size Management**: Configurable file size limits with intelligent truncation
- **Per-User Enumeration**: Automatically discovers and processes all user profiles  
- **Privilege Escalation**: Attempts SeBackup/SeRestore privileges for protected files
- **Graceful Fallbacks**: Multiple collection methods with fallback strategies
- **Comprehensive Manifests**: Each module generates detailed JSON manifests with file hashes, timestamps, and metadata

### Example Module Output Structure
```
artifacts/
├── sysinfo/sysinfo.json
├── windows/
│   ├── evtx/
│   │   ├── Security.evtx
│   │   ├── System.evtx
│   │   └── manifest.json
│   ├── registry/
│   │   ├── system_hives/
│   │   ├── user_hives/
│   │   └── manifest.json
│   ├── browser/
│   │   └── users/
│   │       ├── alice/
│   │       │   ├── chrome/Default/History
│   │       │   └── firefox/profile.default/places.sqlite
│   │       └── bob/...
│   └── [other modules...]
```

## Archive Format

Archives are created as:
- **Unencrypted**: `cryptkeeper_<hostname>_<timestamp>.tar.gz`
- **Encrypted**: `cryptkeeper_<hostname>_<timestamp>.tar.gz.age`

Contents are stored under the `artifacts/` prefix within the archive.

## Development

### Using Make

```bash
# Build the project (Windows binary)
make build

# Build all Windows architectures
make build-all-windows

# Run tests
make test

# Run linter
make lint

# Clean build artifacts
make clean
```

### Direct Go commands

```bash
# Cross-compile for Windows from any platform
GOOS=windows GOARCH=amd64 go build -o bin/cryptkeeper.exe ./cmd/cryptkeeper

# Build native binary for development/testing
go build -o bin/cryptkeeper ./cmd/cryptkeeper

# Run tests (cross-platform)
go test ./...

# Run linter and static analysis
go vet ./...
golangci-lint run  # If golangci-lint is installed

# Download and update dependencies
go mod tidy

# Build with race detection (for development)
go build -race -o bin/cryptkeeper-debug ./cmd/cryptkeeper

# Build optimized release binary
go build -ldflags="-s -w" -o bin/cryptkeeper-release.exe ./cmd/cryptkeeper
```

### Development Workflow

```bash
# 1. Make changes to code
# 2. Run tests to ensure functionality
go test ./...

# 3. Build and test on target platform
GOOS=windows GOARCH=amd64 go build -o bin/cryptkeeper.exe ./cmd/cryptkeeper

# 4. Test basic functionality (if on Windows)
bin/cryptkeeper.exe harvest --help

# 5. Run static analysis
go vet ./...
```

## Project Structure

```
.
├── go.mod                              # Go module definition
├── Makefile                            # Build automation
├── README.md                           # This file
├── cmd/
│   └── cryptkeeper/
│       └── main.go                     # Application entry point
└── internal/
    ├── cli/
    │   ├── root.go                     # Root command implementation
    │   └── harvest.go                  # Harvest command logic
    ├── core/
    │   ├── run.go                      # Module orchestration framework
    │   ├── pack.go                     # Bundling and encryption
    │   └── util.go                     # Utility functions
    ├── modules/
    │   ├── sysinfo/                    # Cross-platform system information
    │   ├── win_evtx/                   # Windows Event Logs collection
    │   ├── win_registry/               # Windows Registry hives
    │   ├── win_prefetch/               # Windows Prefetch files
    │   ├── win_amcache/                # Application Compatibility cache
    │   ├── win_jumplists/              # Windows Jump Lists
    │   ├── win_lnk/                    # Windows LNK shortcut files
    │   ├── win_srum/                   # System Resource Usage Monitor
    │   ├── win_bits/                   # Background Intelligent Transfer Service
    │   ├── win_tasks/                  # Windows Scheduled Tasks
    │   ├── win_services_drivers/       # System drivers and services
    │   ├── win_wmi/                    # WMI repository and subscriptions
    │   ├── win_firewall_net/           # Windows Firewall and network config
    │   ├── win_rdp/                    # RDP artifacts and bitmap cache
    │   ├── win_usb/                    # USB device installation logs
    │   ├── win_browser/                # Browser artifacts (Chrome/Edge/Firefox)
    │   ├── win_recyclebin/             # Recycle Bin artifacts
    │   ├── win_iis/                    # IIS web server logs
    │   ├── win_networkinfo/            # Network configuration and DNS cache
    │   ├── win_systemconfig/           # System configuration and services
    │   ├── win_memory_process/         # Memory and process artifacts
    │   ├── win_applications/           # Application-specific artifacts
    │   ├── win_persistence/            # Persistence mechanisms and malware hunting
    │   ├── win_modern/                 # Cloud and modern Windows artifacts
    │   ├── win_mft/                    # NTFS Master File Table metadata
    │   ├── win_usn/                    # NTFS USN Journal information
    │   ├── win_vss/                    # Volume Shadow Copy Service
    │   ├── win_fileshares/             # File shares and permissions
    │   ├── win_lsa/                    # LSA policy and authentication
    │   ├── win_kerberos/               # Kerberos tickets and configuration
    │   ├── win_logon/                  # Logon sessions and authentication history
    │   ├── win_tokens/                 # Access tokens and privileges
    │   ├── win_ads/                    # Alternate Data Streams detection
    │   ├── win_signatures/             # File signatures and digital certificates
    │   ├── win_certificates/           # Certificate stores and PKI
    │   └── win_trustedinstaller/       # TrustedInstaller and system integrity
    ├── winutil/                        # Windows-specific utilities
    │   ├── privileges_windows.go       # Privilege escalation helpers
    │   ├── filecopy_windows.go         # File copying with backup semantics
    │   ├── process_windows.go          # Command execution helpers
    │   └── sizecaps.go                 # Size constraint management
    ├── parse/
    │   ├── since.go                    # Time parsing utilities
    │   ├── validate.go                 # Validation functions
    │   └── types.go                    # Legacy data structures
    └── schema/
        └── run_output.go               # JSON output schema
```

## Dependencies

- **[github.com/spf13/cobra](https://github.com/spf13/cobra)**: CLI framework
- **[filippo.io/age](https://filippo.io/age)**: Age encryption library
- **[golang.org/x/sys](https://golang.org/x/sys)**: System call extensions

## Platform Compatibility

Cryptkeeper is built with Go and compiles cross-platform, but is optimized for Windows DFIR:

- **Windows**: Full functionality with 35+ specialized collection modules
- **Linux/macOS**: Basic SysInfo module only (Windows modules are no-op)
- **Cross-compilation**: Build Windows binaries from any platform

## Use Cases

### Incident Response
- Rapid triage collection from compromised Windows systems
- Remote deployment via admin shares or EDR tools
- Automated collection with encryption for secure transport

### Digital Forensics  
- Comprehensive artifact collection for forensic analysis
- Timeline reconstruction support via extensive metadata
- Preserved file hashes for evidence integrity

### Compliance & Audit
- System state documentation and evidence collection
- Secure packaging with age encryption for data protection
- Detailed manifests for audit trails

## Security Notes

- Age encryption uses X25519 public keys for secure artifact encryption
- Temporary directories are automatically cleaned up (unless `--keep-tmp` is used)
- All file operations use streaming I/O to minimize memory usage
- Module execution is isolated with individual timeouts and error handling
- Backup privileges automatically enabled when available for protected files
- No network communication - fully offline operation
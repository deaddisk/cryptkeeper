# cryptkeeper

A DFIR (Digital Forensics and Incident Response) CLI tool for collecting system artifacts and packaging them securely.

## Installation

### Using Make (if available)

```bash
make build
```

### Direct Go build

```cmd
REM Download dependencies
go mod tidy

REM Build the project
go build -o bin/cryptkeeper.exe ./cmd/cryptkeeper
```

Both methods create the binary at `bin/cryptkeeper.exe`.

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
  "modules_run": ["sysinfo"],
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
  "modules_run": ["sysinfo"],
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

The current MVP collects:

### SysInfo Module

Collects basic system information into `artifacts/sysinfo/sysinfo.json`:

```json
{
  "os": "windows",
  "arch": "amd64", 
  "hostname": "DESKTOP-ABC123",
  "time_utc": "2025-08-27T12:34:56Z",
  "uptime_seconds": 123456,
  "boot_time_utc": "2025-08-25T10:14:20Z"
}
```

## Archive Format

Archives are created as:
- **Unencrypted**: `cryptkeeper_<hostname>_<timestamp>.tar.gz`
- **Encrypted**: `cryptkeeper_<hostname>_<timestamp>.tar.gz.age`

Contents are stored under the `artifacts/` prefix within the archive.

## Development

### Using Make

```bash
# Build the project
make build

# Run tests
make test

# Run linter
make lint

# Clean build artifacts
make clean
```

### Direct Go commands

```cmd
REM Build the project
go build -o bin/cryptkeeper.exe ./cmd/cryptkeeper

REM Run tests
go test ./...

REM Run linter
go vet ./...

REM Download dependencies
go mod tidy
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
    │   └── sysinfo/
    │       ├── sysinfo.go              # SysInfo module (cross-platform)
    │       ├── sysinfo_linux.go        # Linux uptime implementation
    │       ├── sysinfo_windows.go      # Windows uptime implementation  
    │       ├── sysinfo_darwin.go       # macOS uptime implementation
    │       └── sysinfo_other.go        # Fallback for other OSes
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

## Security Notes

- Age encryption uses X25519 public keys for secure artifact encryption
- Temporary directories are automatically cleaned up (unless `--keep-tmp` is used)
- All file operations use streaming I/O to minimize memory usage
- Module execution is isolated with individual timeouts and error handling
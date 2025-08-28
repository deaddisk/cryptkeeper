SYSTEM / ROLE:
You are an expert Go developer and CLI designer. Generate production-quality, idiomatic Go (1.22+). Keep modules small, testable, and well-commented. Use only the standard library plus cobra (and its transitive deps). Output must compile and run cross-platform.

TASK (MVP DRY-RUN ONLY):
Create a new Go project named cryptkeeper. Implement a cobra based CLI with a root command and a harvest subcommand. This MVP should only parse flags, validate/normalize them, and print a single JSON object to stdout. It must not read files, collect artifacts, open the network, or upload anything—dry-run only.

Functional requirements

Commands

Root command: cryptkeeper → shows concise help and exits 0 if no subcommand is provided.

Subcommand: cryptkeeper harvest → parses flags, prints JSON summary, exits.

Flags (on harvest)

--since (string, optional): either an RFC3339 timestamp or a human duration like 7d, 72h, 15m, 30s, 2w (weeks). Empty = “unset”.

--cap-mb (int, default 0): maximum total MB; 0 means “no cap”. Must be >= 0.

--s3-presigned (string, optional): HTTP(S) presigned URL. If provided, implies an upload intent (but remember, this MVP must not upload).

--sftp (string, optional): SFTP URI like sftp://user@host:22/path or sftp://host/path. If provided, implies upload intent (but do not upload).

--encrypt-age (string, optional): Age public key (should start with age1). If either --s3-presigned or --sftp is set, this key is REQUIRED (policy check only in this MVP).

Normalization

If --since is a duration, compute nowUTC - duration and output the result as RFC3339 (seconds precision). Treat 1w == 7d, 1d == 24h. Use the system clock in UTC.

If --since is RFC3339, pass it through unchanged (but verify it parses).

Validation

--cap-mb >= 0 (error if negative).

--s3-presigned: must start with http:// or https://.

--sftp: must start with sftp://.

Upload policy: if --s3-presigned or --sftp is set, require --encrypt-age starting with age1; otherwise, return an error (MVP only checks policy, does not encrypt or upload).

Output

Print exactly one compact JSON object to stdout with the following keys (no extra logging or banners):

{
"command": "harvest",
"dry_run": true,
"since_input": "<raw or empty>",
"since_normalized_rfc3339": "<rfc3339 or empty>",
"cap_mb": <int>,
"s3_presigned_set": <true|false>,
"sftp_set": <true|false>,
"encrypt_age_set": <true|false>,
"upload_intent": "none|s3|sftp|both",
"encryption_required": <true|false>,
"encryption_supplied": <true|false>,
"ready_to_upload": <true|false>,  // true only if policy satisfied (intent implies encryption and key present)
"timestamp_utc": "<rfc3339 time CLI ran>"
}


All errors must go to stderr and exit with code 1.

Non-goals in this MVP

Do not touch disk (beyond the binary itself), do not open the network, do not upload or encrypt. This is a parser + reporter only.

Project layout (create real files with code)
.
├─ go.mod
├─ Makefile
├─ README.md
├─ cmd/
│  └─ cryptkeeper/
│     └─ main.go              // minimal: init root cmd and execute
└─ internal/
├─ cli/
│  ├─ root.go              // root command
│  └─ harvest.go           // subcommand logic and flags
└─ parse/
├─ since.go             // parse/normalize since duration/timestamp
├─ validate.go          // validators and policy checks
└─ types.go             // small structs for normalized values & output

Implementation details

Cobra wiring: place command assembly in internal/cli. cmd/cryptkeeper/main.go should only call a small cli.Execute() function.

Parsing & normalization:

Create pure functions in internal/parse:

NormalizeSince(input string, now time.Time) (normalizedRFC3339 string, wasSet bool, err error)

Accept duration units: ns, us, µs, ms, s, m, h, d, w. Map d->24h, w->7d.

If empty, return wasSet=false and empty normalized value.

If RFC3339 parse succeeds, return it directly.

Else if duration parse succeeds, compute nowUTC - duration, format RFC3339 (truncate to seconds).

ValidateCapMB(n int) error

ValidateS3URL(s string) (set bool, err error)

ValidateSFTPURI(s string) (set bool, err error)

ValidateAgeKey(s string) (set bool, err error) // set=true only if non-empty and starts with age1

ComputePolicy(uploadIntent string, encryptAgeSet bool) (encryptionRequired bool, readyToUpload bool)

Upload intent logic:

If both --s3-presigned and --sftp are set → upload_intent="both".

If only one is set → upload_intent="s3" or "sftp".

If none set → "none".

encryption_required is true if intent ≠ "none". ready_to_upload is true iff encryption_required && encrypt_age_set.

Output JSON:

Create a dedicated struct for the JSON. Marshal with encoding/json (no pretty-print).

Ensure only the JSON line is printed to stdout; any diagnostics go to stderr.

Error handling:

Aggregate validation errors where sensible and present the first critical one; keep messages clear (e.g., invalid --cap-mb: must be >= 0).

Exit 1 on error.

Developer experience

Makefile:

build: go build -o bin/cryptkeeper ./cmd/cryptkeeper

test: go test ./...

lint: go vet ./...

README.md: Brief usage with examples below.

Write concise package docs at top of each file in internal/parse.

Example CLI sessions (timestamps are illustrative)

Duration + all destinations (policy satisfied)

$ cryptkeeper harvest \
--since 7d \
--cap-mb 2048 \
--s3-presigned https://example.com/presigned?X-Amz-Signature=... \
--sftp sftp://user@host:22/evidence \
--encrypt-age age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq

{"command":"harvest","dry_run":true,"since_input":"7d","since_normalized_rfc3339":"2025-08-19T21:00:00Z","cap_mb":2048,"s3_presigned_set":true,"sftp_set":true,"encrypt_age_set":true,"upload_intent":"both","encryption_required":true,"encryption_supplied":true,"ready_to_upload":true,"timestamp_utc":"2025-08-26T21:00:00Z"}


RFC3339 + S3 only (missing key → error)

$ cryptkeeper harvest --since 2025-08-20T00:00:00Z --s3-presigned https://x
error: encryption required when upload is requested; provide --encrypt-age (age1...)
(exit 1)


No uploads (no encryption required)

$ cryptkeeper harvest --cap-mb 0
{"command":"harvest","dry_run":true,"since_input":"","since_normalized_rfc3339":"","cap_mb":0,"s3_presigned_set":false,"sftp_set":false,"encrypt_age_set":false,"upload_intent":"none","encryption_required":false,"encryption_supplied":false,"ready_to_upload":false,"timestamp_utc":"2025-08-26T21:00:00Z"}


Bad inputs

$ cryptkeeper harvest --cap-mb -1
invalid --cap-mb: must be >= 0
(exit 1)

$ cryptkeeper harvest --since not-a-time
invalid --since: must be RFC3339 or a duration like 7d, 72h, 15m, 30s, 2w
(exit 1)

$ cryptkeeper harvest --sftp example.com/path
invalid --sftp: must start with sftp://
(exit 1)

Deliverables

All source files per tree above (no TODOs).

Compilable code; make build works.

Dry-run behavior only; no disk/network actions beyond printing JSON.

Now generate the complete project (all files) in a single response.
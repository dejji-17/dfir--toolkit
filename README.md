# File Integrity Monitor (FIM)

File Integrity Monitoring is a core control in incident response. Attackers
often modify system files to maintain persistence or cover their tracks. A FIM
tool simulates the chain-of-custody verification used in real forensic
investigations — creating a trusted baseline and detecting unauthorized
changes.

This project is my first step into building practical forensics tooling in
Python.

This project demonstrates the baseline-and-compare concept; by itself, it does
not establish formal chain of custody. See
[Scope and limitations](#scope-and-limitations).

A small Python command-line tool for recording and checking file integrity. It
calculates a SHA-256 hash and records the filesystem modification time for each
file in a directory tree, then saves the results in a JSON baseline. A later
verification compares the current files with that baseline and reports new,
modified, deleted, or timestamp-only changes.

## Requirements

- Python 3.10 or later
- No third-party packages

Run the commands below from the project directory containing `fim.py` and
`test_fim.py`.

## Quick start

Create a small directory to monitor and put a sample file in it:

```powershell
New-Item -ItemType Directory -Force .\test_data
Set-Content .\test_data\example.txt "First test file"
```

Create a baseline:

```powershell
python fim.py scan .\test_data .\baseline.json
```

The baseline is written to `baseline.json`. Keep it outside the directory being
monitored so the tool does not include its own record in the scan.

Verify the directory against the baseline:

```powershell
python fim.py verify .\test_data .\baseline.json
```

If nothing has changed, the tool prints:

```text
No changes detected.
```

Try changing a file and verifying again:

```powershell
Set-Content .\test_data\example.txt "Changed for testing"
python fim.py verify .\test_data .\baseline.json
```

The output will identify the file as `[MODIFIED]`. Verification can also report
`[NEW]` files that were not in the baseline and `[DELETED]` files that are no
longer present. If a file's timestamp changes but its contents do not, it
reports `[TIMESTAMP CHANGED]`. Change reports include the baseline and current
filesystem modification times in UTC when available.

### Check one saved file

For a single file, create and check its baseline with just the file path:

```powershell
python fim.py scan-file "C:\path\to\important.txt"
python fim.py verify-file "C:\path\to\important.txt"
```

By default, the baseline is saved beside the file as
`important.txt.fim.json`. You can supply a different baseline path as an
optional second argument. Keep a trusted copy of the baseline separately if
you need protection against someone changing both the file and its baseline.

## Commands

```text
python fim.py scan <directory> <baseline.json>
python fim.py verify <directory> <baseline.json>
python fim.py scan-file <file> [baseline.json]
python fim.py verify-file <file> [baseline.json]
```

- `scan` recursively hashes files and creates or replaces the baseline.
- `verify` compares the current files with the baseline.
- `scan-file` creates a baseline for one file; the baseline defaults to
  `<file>.fim.json`.
- `verify-file` checks one file against that baseline.

Paths can be relative to the current working directory or absolute paths. If
the baseline is inside the monitored directory, it is excluded from scanning.
Filesystem errors are reported; an incomplete scan does not produce a
successful comparison or baseline.

## Exit codes

- `0` — scan succeeded, or verification found no changes.
- `1` — verification found one or more changes.
- `2` — an input, baseline, or filesystem error occurred.

## Run the tests

From the project directory:

```powershell
python -m unittest -v test_fim
```

The tests use temporary directories and cover creating/verifying a baseline,
nested files, all three change types, excluding a baseline inside the scan
directory, and handling invalid or missing inputs.

## Scope and limitations

This is a learning project and a basic integrity checker, not a complete
forensic acquisition or chain-of-custody system. The baseline includes its
creation time, each file's filesystem last-modified time (UTC), and file hashes.
Verification reports content changes and timestamp-only changes separately.
Filesystem timestamps can be changed or forged; they are not proof of exactly
when content changed. The baseline is not signed or protected from tampering,
so store a trusted copy securely if you rely on it for comparisons. SHA-256
detects content changes; it does not identify who made a change or when it
happened.
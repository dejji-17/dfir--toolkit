"""A small SHA-256 file integrity monitor."""

from __future__ import annotations

# Standard-library tools for the CLI, hashing, JSON, filesystem traversal,
# temporary files, timestamps, and path handling.
import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

CHUNK_SIZE = 1024 * 1024
BASELINE_VERSION = 1
HASH_ALGORITHM = "sha256"
HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class FimError(Exception):
    """An expected input or filesystem error."""


def hash_file(path: Path) -> str:
    """Return a file's SHA-256 digest, reading it in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        # Read bytes in chunks so hashing large files does not use large amounts of memory.
        for chunk in iter(lambda: file_handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_modified_at(path: Path) -> str:
    """Return a file's last-modified timestamp in UTC."""
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()


def collect_hashes(
    root: Path, excluded_file: Path
) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """Hash regular files below root, record timestamps, and report errors."""
    hashes: dict[str, str] = {}
    modified_at: dict[str, str] = {}
    errors: list[str] = []
    # Resolve both paths so the baseline is excluded even when given via a relative path.
    excluded = excluded_file.resolve()

    def on_walk_error(error: OSError) -> None:
        errors.append(f"{error.filename or root}: {error.strerror or error}")

    for current_dir, directories, filenames in os.walk(root, onerror=on_walk_error):
        directories.sort()
        filenames.sort()
        for filename in filenames:
            path = Path(current_dir) / filename
            try:
                if path.resolve() == excluded or not path.is_file():
                    continue
                # POSIX-style relative paths keep the baseline format consistent across OSes.
                relative_path = path.relative_to(root).as_posix()
                hashes[relative_path] = hash_file(path)
                modified_at[relative_path] = file_modified_at(path)
            except OSError as error:
                errors.append(f"{path}: {error}")

    return hashes, modified_at, errors


def read_baseline(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Load and validate baseline hashes and optional modification timestamps."""
    try:
        with path.open("r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)
    except (OSError, json.JSONDecodeError) as error:
        raise FimError(f"could not read baseline {path}: {error}") from error

    if not isinstance(data, dict):
        raise FimError(f"invalid baseline {path}: expected a JSON object")
    if data.get("version") != BASELINE_VERSION:
        raise FimError(f"invalid baseline {path}: unsupported or missing version")
    if data.get("algorithm") != HASH_ALGORITHM:
        raise FimError(f"invalid baseline {path}: expected {HASH_ALGORITHM}")

    files = data.get("files")
    if not isinstance(files, dict):
        raise FimError(f"invalid baseline {path}: 'files' must be an object")

    # Reject malformed entries before using baseline paths or hashes in comparisons.
    for relative_path, digest in files.items():
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or not isinstance(digest, str)
            or HASH_PATTERN.fullmatch(digest) is None
        ):
            raise FimError(f"invalid baseline {path}: malformed file entry")

    modified_at = data.get("file_modified_at", {})
    if not isinstance(modified_at, dict):
        raise FimError(f"invalid baseline {path}: 'file_modified_at' must be an object")
    for relative_path, timestamp in modified_at.items():
        if (
            relative_path not in files
            or not isinstance(timestamp, str)
            or not _is_timezone_aware_timestamp(timestamp)
        ):
            raise FimError(f"invalid baseline {path}: malformed modification timestamp")

    return files, modified_at


def _is_timezone_aware_timestamp(value: str) -> bool:
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return False
    return timestamp.tzinfo is not None and timestamp.utcoffset() is not None


def write_baseline(
    path: Path, hashes: dict[str, str], modified_at: dict[str, str]
) -> None:
    """Write a complete baseline and atomically replace any previous one."""
    data = {
        "version": BASELINE_VERSION,
        "algorithm": HASH_ALGORITHM,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "file_modified_at": modified_at,
        "files": hashes,
    }
    temporary_path: Path | None = None
    try:
        # Write beside the destination so replacing it is an atomic filesystem operation.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as file_handle:
            temporary_path = Path(file_handle.name)
            json.dump(data, file_handle, indent=2, sort_keys=True)
            file_handle.write("\n")
        temporary_path.replace(path)
    except OSError as error:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError as cleanup_error:
                raise FimError(
                    f"could not write baseline {path}: {error}; "
                    f"could not remove temporary file {temporary_path}: {cleanup_error}"
                ) from cleanup_error
        raise FimError(f"could not write baseline {path}: {error}") from error


def scan_command(root_arg: Path, baseline_arg: Path) -> int:
    root = root_arg.resolve()
    if not root.is_dir():
        raise FimError(f"scan directory does not exist or is not a directory: {root_arg}")

    baseline = baseline_arg.resolve()
    hashes, modified_at, errors = collect_hashes(root, baseline)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        raise FimError("scan was incomplete; baseline was not written")

    write_baseline(baseline, hashes, modified_at)
    print(f"Baseline saved: {baseline}")
    print(f"Files recorded: {len(hashes)}")
    return 0


def verify_command(root_arg: Path, baseline_arg: Path) -> int:
    root = root_arg.resolve()
    if not root.is_dir():
        raise FimError(f"scan directory does not exist or is not a directory: {root_arg}")

    baseline = baseline_arg.resolve()
    expected, expected_modified_at = read_baseline(baseline)
    current, current_modified_at, errors = collect_hashes(root, baseline)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        raise FimError("verification was incomplete; no comparison was reported")

    expected_paths = set(expected)
    current_paths = set(current)
    changes: list[tuple[str, str]] = []
    # Files present only in the baseline were deleted from the monitored directory.
    for relative_path in sorted(expected_paths - current_paths):
        changes.append(("DELETED", relative_path))
    # Shared paths are modified only if their content fingerprints differ.
    for relative_path in sorted(expected_paths & current_paths):
        if expected[relative_path] != current[relative_path]:
            changes.append(("MODIFIED", relative_path))
        elif (
            relative_path in expected_modified_at
            and expected_modified_at[relative_path] != current_modified_at[relative_path]
        ):
            changes.append(("TIMESTAMP CHANGED", relative_path))
    # Files present only in the current scan are new.
    for relative_path in sorted(current_paths - expected_paths):
        changes.append(("NEW", relative_path))

    if changes:
        for status, relative_path in changes:
            print(f"[{status}] {relative_path}")
            baseline_time = expected_modified_at.get(relative_path)
            current_time = current_modified_at.get(relative_path)
            if baseline_time is not None:
                print(f"  Baseline last modified (UTC): {baseline_time}")
            if current_time is not None:
                print(f"  Current last modified (UTC): {current_time}")
            if status == "MODIFIED":
                print("  Content hash changed.")
            elif status == "TIMESTAMP CHANGED":
                print("  Content hash is unchanged; only the timestamp changed.")
        print(f"Changes found: {len(changes)}")
        return 1

    print("No changes detected.")
    return 0


def default_file_baseline(file_path: Path) -> Path:
    """Return the default sidecar baseline path for one monitored file."""
    return file_path.with_name(f"{file_path.name}.fim.json")


def scan_file_command(file_arg: Path, baseline_arg: Path | None) -> int:
    file_path = file_arg.resolve()
    if not file_path.is_file():
        raise FimError(f"file does not exist or is not a regular file: {file_arg}")

    baseline = (baseline_arg or default_file_baseline(file_path)).resolve()
    if baseline == file_path:
        raise FimError("baseline path must not be the same as the monitored file")

    try:
        digest = hash_file(file_path)
    except OSError as error:
        raise FimError(f"could not read file {file_path}: {error}") from error

    modified_at = {file_path.name: file_modified_at(file_path)}
    write_baseline(baseline, {file_path.name: digest}, modified_at)
    print(f"Baseline saved: {baseline}")
    print(f"File recorded: {file_path}")
    return 0


def verify_file_command(file_arg: Path, baseline_arg: Path | None) -> int:
    file_path = file_arg.resolve()
    baseline = (baseline_arg or default_file_baseline(file_path)).resolve()
    expected, expected_modified_at = read_baseline(baseline)
    expected_digest = expected.get(file_path.name)
    if expected_digest is None:
        raise FimError(f"baseline {baseline} does not contain {file_path.name}")

    if not file_path.is_file():
        print(f"[DELETED] {file_path.name}")
        baseline_time = expected_modified_at.get(file_path.name)
        if baseline_time is not None:
            print(f"  Baseline last modified (UTC): {baseline_time}")
        print("Changes found: 1")
        return 1

    try:
        current_digest = hash_file(file_path)
        current_modified_at = file_modified_at(file_path)
    except OSError as error:
        raise FimError(f"could not read file {file_path}: {error}") from error

    if current_digest != expected_digest:
        print(f"[MODIFIED] {file_path.name}")
        baseline_time = expected_modified_at.get(file_path.name)
        if baseline_time is not None:
            print(f"  Baseline last modified (UTC): {baseline_time}")
        print(f"  Current last modified (UTC): {current_modified_at}")
        print("Changes found: 1")
        return 1

    baseline_time = expected_modified_at.get(file_path.name)
    if baseline_time is not None and baseline_time != current_modified_at:
        print(f"[TIMESTAMP CHANGED] {file_path.name}")
        print(f"  Baseline last modified (UTC): {baseline_time}")
        print(f"  Current last modified (UTC): {current_modified_at}")
        print("  Content hash is unchanged; only the timestamp changed.")
        print("Changes found: 1")
        return 1

    print("No changes detected.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and verify SHA-256 file integrity baselines."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan_parser = commands.add_parser("scan", help="create or replace a baseline")
    scan_parser.add_argument("directory", type=Path, help="directory to monitor")
    scan_parser.add_argument("baseline", type=Path, help="JSON baseline file")

    verify_parser = commands.add_parser("verify", help="compare files with a baseline")
    verify_parser.add_argument("directory", type=Path, help="directory to monitor")
    verify_parser.add_argument("baseline", type=Path, help="JSON baseline file")

    scan_file_parser = commands.add_parser(
        "scan-file", help="create a baseline for one file"
    )
    scan_file_parser.add_argument("file", type=Path, help="file to monitor")
    scan_file_parser.add_argument(
        "baseline",
        type=Path,
        nargs="?",
        help="JSON baseline file (default: <file>.fim.json)",
    )

    verify_file_parser = commands.add_parser(
        "verify-file", help="check one file against its baseline"
    )
    verify_file_parser.add_argument("file", type=Path, help="file to check")
    verify_file_parser.add_argument(
        "baseline",
        type=Path,
        nargs="?",
        help="JSON baseline file (default: <file>.fim.json)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return scan_command(args.directory, args.baseline)
        if args.command == "verify":
            return verify_command(args.directory, args.baseline)
        if args.command == "scan-file":
            return scan_file_command(args.file, args.baseline)
        return verify_file_command(args.file, args.baseline)
    except FimError as error:
        # Keep expected operational errors readable and distinguishable from detected changes.
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
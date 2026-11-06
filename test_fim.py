import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import fim


class FileIntegrityMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        # Each test gets an isolated directory and baseline to avoid affecting user files.
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name) / "monitored"
        self.root.mkdir()
        self.baseline = Path(self.temporary_directory.name) / "baseline.json"

    def run_cli(self, *arguments: str) -> tuple[int, str, str]:
        # Capture CLI output so tests can assert both exit status and reported results.
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = fim.main(list(arguments))
        return result, stdout.getvalue(), stderr.getvalue()

    def test_scan_and_unchanged_verify(self) -> None:
        # A file in a nested folder should be included and remain unchanged on verification.
        (self.root / "nested").mkdir()
        (self.root / "nested" / "note.txt").write_text("original", encoding="utf-8")

        result, output, error = self.run_cli("scan", str(self.root), str(self.baseline))

        self.assertEqual(result, 0, error)
        self.assertIn("Files recorded: 1", output)
        baseline_data = json.loads(self.baseline.read_text(encoding="utf-8"))
        self.assertEqual(baseline_data["algorithm"], "sha256")
        self.assertIn("nested/note.txt", baseline_data["files"])

        result, output, error = self.run_cli("verify", str(self.root), str(self.baseline))

        self.assertEqual(result, 0, error)
        self.assertIn("No changes detected.", output)

    def test_verify_reports_modified_new_and_deleted_files(self) -> None:
        # Build a baseline, then make one example of each supported change type.
        (self.root / "modified.txt").write_text("before", encoding="utf-8")
        (self.root / "deleted.txt").write_text("gone", encoding="utf-8")
        result, _, error = self.run_cli("scan", str(self.root), str(self.baseline))
        self.assertEqual(result, 0, error)

        (self.root / "modified.txt").write_text("after", encoding="utf-8")
        (self.root / "deleted.txt").unlink()
        (self.root / "new.txt").write_text("added", encoding="utf-8")

        result, output, error = self.run_cli("verify", str(self.root), str(self.baseline))

        self.assertEqual(result, 1, error)
        self.assertIn("[MODIFIED] modified.txt", output)
        self.assertIn("[DELETED] deleted.txt", output)
        self.assertIn("[NEW] new.txt", output)

    def test_baseline_inside_monitored_directory_is_excluded(self) -> None:
        # The baseline must not be detected as a new or changing monitored file.
        baseline = self.root / "baseline.json"
        (self.root / "file.txt").write_text("content", encoding="utf-8")

        result, _, error = self.run_cli("scan", str(self.root), str(baseline))

        self.assertEqual(result, 0, error)
        result, output, error = self.run_cli("verify", str(self.root), str(baseline))

        self.assertEqual(result, 0, error)
        self.assertIn("No changes detected.", output)

    def test_invalid_baseline_fails_explicitly(self) -> None:
        # Verification should reject malformed JSON instead of treating it as empty.
        self.baseline.write_text("not json", encoding="utf-8")

        result, _, error = self.run_cli("verify", str(self.root), str(self.baseline))

        self.assertEqual(result, 2)
        self.assertIn("could not read baseline", error)

    def test_missing_directory_fails_explicitly(self) -> None:
        # A missing scan root is an error, not an empty directory.
        missing = self.root / "missing"

        result, _, error = self.run_cli("scan", str(missing), str(self.baseline))

        self.assertEqual(result, 2)
        self.assertIn("does not exist or is not a directory", error)


if __name__ == "__main__":
    unittest.main()

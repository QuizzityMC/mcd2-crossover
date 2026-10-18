from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"helper"))
import json
import sys
import time
import unittest
from bounded_capture import capture, capture_pair


def python(source):
    return [sys.executable, "-u", "-c", source]


class DeadlineTests(unittest.TestCase):
    def test_context_hang_preserves_baseline_and_last_thread(self):
        baseline = python('print(\'{"threads":[{"tid":42,"suspend_count":0}]}\')')
        stuck = python('import sys,time; print(\'{"phase":"thread_context","tid":42}\',file=sys.stderr); time.sleep(30)')
        started = time.monotonic()
        result = capture_pair(baseline, stuck, timeout=0.3)
        self.assertTrue(result["baseline"]["report_complete"])
        self.assertEqual(result["baseline"]["report"]["threads"][0]["tid"], 42)
        self.assertEqual(result["context"]["stop_reason"], "deadline")
        self.assertEqual(result["context"]["last_phase"]["tid"], 42)
        self.assertLess(time.monotonic()-started, 2)

    def test_failed_baseline_skips_context(self):
        result = capture_pair(python('raise SystemExit(3)'), ["nonexistent-command"])
        self.assertIsNone(result["context"])

    def test_stderr_not_copied_into_export(self):
        result = capture(python('import sys; print("private path and token",file=sys.stderr); print("{}")'))
        self.assertNotIn("private path", json.dumps(result))
        self.assertEqual(result["ignored_stderr_lines"], 1)

    def test_output_cap(self):
        result = capture(python('import sys,time; sys.stdout.write("x"*100000); sys.stdout.flush(); time.sleep(30)'), limit=1024)
        self.assertEqual(result["stop_reason"], "output_limit")
        self.assertFalse(result["report_complete"])

    def test_closed_pipes_dont_escape_deadline(self):
        result = capture(python('import os,time; os.close(1); os.close(2); time.sleep(30)'), timeout=0.3)
        self.assertEqual(result["stop_reason"], "deadline_after_output_closed")


if __name__ == "__main__":
    unittest.main()

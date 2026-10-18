from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"helper"))
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from capture_selected import capture_selected


class CheckpointTests(unittest.TestCase):
    def test_baseline_is_on_disk_before_context_can_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)/'capture.json'
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                if len(calls) == 1:
                    return {'report_complete':True,'report':{'matched_count':1,'windows_pid':42,'creation_time':123}}
                if len(calls) == 2:
                    self.assertEqual(kwargs['env']['MCD2_CAPTURE_EXPECTED_CREATED'],'123')
                    return {'report_complete':True,'report':{'threads':[{'tid':7,'suspend_count':0}]}}
                saved = json.loads(output.read_text())
                self.assertEqual(saved['status'],'capturing_context')
                self.assertEqual(saved['baseline']['report']['threads'][0]['tid'],7)
                raise OSError('simulated launch failure')
            with patch('capture_selected.capture',side_effect=run):
                with self.assertRaises(OSError):
                    capture_selected(['wine'],folder,'C:\\target.exe',output)
            self.assertEqual(json.loads(output.read_text())['baseline']['report']['threads'][0]['tid'],7)


if __name__ == '__main__':
    unittest.main()

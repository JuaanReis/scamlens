import struct
import unittest
from scfs import run_engine, Settings
from scfs.heuristics import get_rules
from scfs.scoring.evidence import grouped_score
from scfs.tests.test_engine import pe, elf, SUSPICIOUS


def rule(scan, name):
    return next(r for r in scan['heuristics'] if r['name'] == name)


class NewRuleTests(unittest.TestCase):
    def test_25_distinct_rules(self):
        rules=get_rules()
        self.assertEqual(len(rules),25)
        self.assertEqual(len({r.name for r in rules}),25)
        self.assertTrue(all(r.extra.get('group') for r in rules))

    def test_capability_pairs(self):
        cases={
          'input_capture':(b'GetAsyncKeyState GetForegroundWindow', b'GetAsyncKeyState'),
          'screen_capture':(b'BitBlt GetDC', b'BitBlt'),
          'clipboard_capture':(b'GetClipboardData OpenClipboard', b'GetClipboardData'),
          'service_installation':(b'CreateService OpenSCManager',b'CreateService'),
          'token_manipulation':(b'DuplicateTokenEx OpenProcessToken',b'DuplicateTokenEx'),
          'ransomware_artifacts':(b'your files have been encrypted CryptEncrypt WriteFile',b'CryptEncrypt'),
          'data_exfiltration':(b'UploadFile wallet.dat Compress-Archive',b'UploadFile'),
          'suspicious_lolbin':(b'mshta https://example.invalid FromBase64String',b'mshta'),
        }
        for name,(strong,weak) in cases.items():
            with self.subTest(rule=name):
                a,_=run_engine(strong,name='fixture.ps1')
                b,_=run_engine(weak,name='fixture.ps1')
                c,_=run_engine(b'hello world',name='fixture.ps1')
                self.assertGreater(rule(a,name)['score'],rule(b,name)['score'])
                self.assertEqual(rule(c,name)['score'],0)
                self.assertEqual(a['stats']['rules_failed'],0)

    def test_dynamic_resolution_is_weak(self):
        scan,_=run_engine(pe()+b'\0LoadLibraryA\0GetProcAddress\0')
        self.assertEqual(rule(scan,'dynamic_import_resolution')['score'],.3)
        self.assertLess(scan['result']['score'],25)

    def test_embedded_pe_validation(self):
        scan,_=run_engine(pe()+pe())
        self.assertEqual(rule(scan,'embedded_executable')['score'],.4)
        self.assertEqual(rule(scan,'embedded_executable')['evidence'],['PE header at file offset 1024'])
        scan,_=run_engine(pe()+b'MZ'+b'\0'*100)
        self.assertEqual(rule(scan,'embedded_executable')['score'],0)

    def test_pe_overlapping_sections(self):
        data=bytearray(pe())
        struct.pack_into('<H',data,0x86,2)
        pos=0x98+224
        data[pos+40:pos+80]=data[pos:pos+40]
        data[pos+40:pos+48]=b'.other\0\0'
        scan,_=run_engine(bytes(data))
        self.assertEqual(rule(scan,'overlapping_sections')['score'],.65)
        scan,_=run_engine(elf())
        self.assertIsNone(rule(scan,'overlapping_sections')['score'])

    def test_comments(self):
        for filename,prefix in [('example.py',b'# '),('example.ps1',b'# '),('example.sh',b'# '),('example.cmd',b'REM '),('example.bat',b'::'),('example.js',b'//'),('example.vbs',b"'")]:
            with self.subTest(filename=filename):
                scan,_=run_engine(prefix+b'vssadmin delete shadows\necho hello',name=filename)
                self.assertEqual(rule(scan,'destructive_commands')['score'],0)
                self.assertLess(scan['result']['score'],25)
        scan,_=run_engine(b'vssadmin delete shadows',name='example.ps1')
        self.assertGreaterEqual(scan['result']['score'],25)

    def test_groups_and_legacy(self):
        row=lambda name,group,score,weight=3:dict(name=name,category=group,group=group,score=score,weight=weight)
        original=[row('one','impact',.7)]
        raw,score,meta=grouped_score(original,5)
        self.assertAlmostEqual(raw,.35)
        self.assertGreaterEqual(score,25)
        padded=original+[row('neutral'+str(i),'other'+str(i),0) for i in range(100)]
        self.assertEqual(grouped_score(padded,5)[:2],(raw,score))
        duplicate=original+[row('same_evidence','impact',.7)]
        self.assertEqual(grouped_score(duplicate,5)[:2],(raw,score))
        independent=original+[row('two','injection',.7)]
        self.assertGreater(grouped_score(independent,5)[1],score)
        unknown=[row('unavailable','unknown',None)]
        self.assertIsNone(grouped_score(unknown,5)[1])
        grouped,_=run_engine(SUSPICIOUS,name='fixture.ps1')
        legacy,_=run_engine(SUSPICIOUS,name='fixture.ps1',settings=Settings(score_model='legacy'))
        self.assertEqual(grouped['scoring']['model'],'grouped')
        self.assertEqual(legacy['scoring']['model'],'legacy')
        with self.assertRaises(ValueError):Settings(score_model='typo')

    def test_increasing_evidence_never_reduces_score(self):
        for a in range(11):
            rows=[dict(name=str(i),category=str(i),group=str(i),score=a/10 if i==0 else .2,weight=3) for i in range(5)]
            before=grouped_score(rows,5)[1]
            rows[0]['score']=min(1,a/10+.1)
            self.assertGreaterEqual(grouped_score(rows,5)[1],before)

class CalibrationTests(unittest.TestCase):
    def test_candidate_selection_and_controls(self):
        from scfs.calibration import evaluate
        report=evaluate()
        self.assertEqual(report['selected_k'],5)
        self.assertFalse(report['empirically_calibrated'])
        selected=next(row for row in report['candidates'] if row['k']==5)
        self.assertTrue(all(row['passed'] for row in selected['controls']))
        self.assertFalse(report['candidates'][0]['accepted'])

    def test_holdout_does_not_select_k(self):
        from unittest.mock import patch
        from scfs.calibration import evaluate,controls
        changed=controls()
        for row in changed:
            if row['split']=='holdout':row['minimum']=99
        with patch('scfs.calibration.controls',return_value=changed):report=evaluate()
        self.assertEqual(report['selected_k'],5)
        self.assertTrue(any(not c['passed'] for c in report['candidates'][1]['controls']))

    def test_manifest_rejects_data_leakage(self):
        import json
        import tempfile
        from pathlib import Path
        from scfs.calibration import evaluate
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/'hello.sh').write_text('echo hello')
            (p/'manifest.json').write_text(json.dumps(dict(samples=[
                dict(path='hello.sh',label='benign',split='validation'),
                dict(path='hello.sh',label='benign',split='test')])))
            with self.assertRaises(ValueError):evaluate(manifest=p/'manifest.json')

    def test_embedded_search_limit_is_reported(self):
        scan,_=run_engine(pe()+b'MZ'*100)
        self.assertEqual(scan['status'],'partial')
        self.assertTrue(any('embedded PE' in w for w in scan['warnings']))

if __name__ == '__main__':unittest.main()


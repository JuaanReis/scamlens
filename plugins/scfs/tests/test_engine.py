import contextlib
import io
import json
import math
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest

from scfs import Settings, run_engine
from scfs.scoring.sigmoid import sigmoid
from scfs.scoring.weighted_average import weighted_average
from scfs.heuristics import get_rules


def pe(bits=32, rwx=False):
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    opt_size = 240 if bits == 64 else 224
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664 if bits == 64 else 0x14c, 1, 0, 0, 0, opt_size, 2)
    struct.pack_into('<H', data, 0x98, 0x20b if bits == 64 else 0x10b)
    struct.pack_into('<I', data, 0x98+16, 0x1000)
    pos = 0x98+opt_size
    data[pos:pos+8] = b'.text\0\0\0'
    struct.pack_into('<IIII', data, pos+8, 512, 0x1000, 512, 512)
    struct.pack_into('<I', data, pos+36, 0xe0000020 if rwx else 0x60000020)
    return bytes(data)


def elf(bits=64, endian='<'):
    data = bytearray(512)
    data[:6] = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2])
    if bits == 64:
        struct.pack_into(endian+'HHIQQQIHHHHHH', data, 16, 2, 62, 1, 0x400080, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        struct.pack_into(endian+'IIQQQQQQ', data, 64, 1, 5, 0, 0x400000, 0, 512, 512, 4096)
    else:
        struct.pack_into(endian+'HHIIIIIHHHHHH', data, 16, 2, 3, 1, 0x400080, 52, 0, 0, 52, 32, 1, 0, 0, 0)
        struct.pack_into(endian+'IIIIIIII', data, 52, 1, 0, 0x400000, 0, 512, 512, 5, 4096)
    return bytes(data)


def macho(bits=64, endian='<'):
    data = bytearray(512)
    struct.pack_into(endian+'I', data, 0, 0xfeedfacf if bits == 64 else 0xfeedface)
    size = 72 if bits == 64 else 56
    struct.pack_into(endian+'IIIIII', data, 4, 0x1000007, 3, 2, 1, size, 0)
    pos = 32 if bits == 64 else 28
    struct.pack_into(endian+'II', data, pos, 0x19 if bits == 64 else 1, size)
    data[pos+8:pos+24] = b'__TEXT' + b'\0'*10
    struct.pack_into(endian+('QQQQIIII' if bits == 64 else 'IIIIIIII'), data, pos+24, 0x1000, 512, 0, 512, 5, 5, 0, 0)
    return bytes(data)


SUSPICIOUS = b'''# inert fixture: strings only, never executed
VirtualAllocEx WriteProcessMemory CreateRemoteThread
lsass.exe sekurlsa:: logonpasswords
schtasks /create /etc/cron
Set-MpPreference DisableRealtimeMonitoring amsiInitFailed
vssadmin delete shadows wbadmin delete catalog
DownloadString Invoke-Expression FromBase64String
IsDebuggerPresent CheckRemoteDebuggerPresent
'''


class EngineTests(unittest.TestCase):
    def test_binary_variants(self):
        for data in (pe(32), pe(64), elf(32), elf(64), elf(32,'>'), elf(64,'>'), macho(32), macho(64), macho(32,'>'), macho(64,'>')):
            with self.subTest(magic=data[:6]):
                scan, target = run_engine(data)
                self.assertEqual(scan['status'], 'ok', scan)
                self.assertEqual(scan['stats']['rules_failed'], 0)
                self.assertTrue(target['executable']['sections'])
                self.assertLess(scan['result']['score'], 25)

    def test_fat_macho(self):
        a,b = macho(32),macho(64)
        data = b'\xca\xfe\xba\xbe' + struct.pack('>I',2)
        data += struct.pack('>IIIII',7,3,48,len(a),0)
        data += struct.pack('>IIIII',0x1000007,3,48+len(a),len(b),0)
        scan,target = run_engine(data+a+b)
        self.assertEqual(scan['status'],'ok')
        self.assertEqual(len(target['executable']['architectures']),2)

    def test_scripts_and_ordering(self):
        for extension in ('ps1','bat','cmd','vbs','js','sh','py'):
            low,_ = run_engine(b'echo hello world\n', name='hello.'+extension)
            high,target = run_engine(SUSPICIOUS, name='invoice.pdf.'+extension)
            self.assertEqual(low['status'],'ok')
            self.assertGreater(high['result']['score'], low['result']['score'])
            self.assertGreaterEqual(high['result']['score'],55)
            self.assertNotIn('text', target['executable'])
        scan,_ = run_engine('echo olá'.encode('utf-16'),name='a.ps1')
        self.assertEqual(scan['status'],'ok')

    def test_error_has_no_safe_verdict(self):
        for data in (b'', b'MZ', b'\x7fELF', b'\xcf\xfa\xed\xfe', b'hello'):
            scan,target = run_engine(data)
            self.assertEqual(scan['status'],'error')
            self.assertIsNone(scan['result']['score'])
            self.assertEqual(scan['result']['verdict'],'unknown')
            self.assertEqual(target,{})

    def test_limits(self):
        scan,_ = run_engine(b'x'*100, name='a.py',settings=Settings(max_file_bytes=10))
        self.assertEqual(scan['status'],'error')
        scan,_ = run_engine(b'hello\0world\0other', name='a.exe')
        self.assertEqual(scan['status'],'error')
        scan,_ = run_engine(pe()+b"hello\0world", settings=Settings(max_strings=1))
        self.assertEqual(scan['status'],'partial')
        self.assertTrue(scan['warnings'])

    def test_file_path_and_bytes_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'test.exe'
            path.write_bytes(pe())
            a,ta=run_engine(path)
            b,tb=run_engine(pe(), name=path.name)
            self.assertEqual(a['result'],b['result'])
            self.assertEqual(ta,tb)
            missing,_=run_engine(Path(tmp)/'absent')
            self.assertEqual(missing['status'],'error')

    def test_scoring(self):
        self.assertAlmostEqual(sigmoid([0],[1]),7.585818,places=5)
        self.assertEqual(sigmoid([.5],[1]),50)
        self.assertAlmostEqual(sigmoid([1],[1]),92.414182,places=5)
        self.assertIsNone(sigmoid([None],[1]))
        self.assertEqual(weighted_average([None,.5],[100,1]),.5)
        values=[sigmoid([i/100],[1]) for i in range(101)]
        self.assertEqual(values,sorted(values))
        for k in (0,float('nan'),float('inf'),21):
            with self.assertRaises(ValueError):
                Settings(k=k)

    def test_provider(self):
        class Provider:
            calls=[]
            def lookup(self,digest):
                self.calls.append(digest)
                return dict(malicious=10,total=10,source='fixture')
        provider=Provider()
        plain,_=run_engine(pe())
        report,target=run_engine(pe(),reputation_provider=provider)
        self.assertEqual(len(provider.calls),1)
        self.assertEqual(len(provider.calls[0]),64)
        self.assertGreater(report['result']['score'],plain['result']['score'])
        class Broken:
            def lookup(self,digest):
                raise TimeoutError()
        report,_=run_engine(pe(),reputation_provider=Broken())
        self.assertEqual(report['status'],'partial')
        rule=next(r for r in report['heuristics'] if r['name']=='external_reputation')
        self.assertIsNone(rule['score'])

    def test_disabled(self):
        scan,_=run_engine(pe(),settings=Settings(disabled_rules=tuple(r.name for r in get_rules())))
        self.assertEqual(scan['status'],'inconclusive')
        self.assertIsNone(scan['result']['score'])
        with self.assertRaises(ValueError):
            run_engine(pe(),settings=Settings(disabled_rules=('typo',)))

    def test_truncations_and_mutations(self):
        rng=random.Random(7)
        for original in (pe(),elf(),macho()):
            for i in range(0,len(original),7):
                scan,_=run_engine(original[:i])
                self.assertIn(scan['status'],('ok','partial','error'))
            for _ in range(80):
                data=bytearray(original)
                for _ in range(5):
                    data[rng.randrange(len(data))]=rng.randrange(256)
                scan,_=run_engine(bytes(data))
                self.assertIn(scan['status'],('ok','partial','error'))

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'hello.sh'
            path.write_text('#!/bin/sh\necho hello\n')
            process=subprocess.run([sys.executable,'-m','scfs',str(path),'--json'],capture_output=True,text=True)
            self.assertEqual(process.returncode,0,process.stderr)
            self.assertEqual(json.loads(process.stdout)['scan']['status'],'ok')
            process=subprocess.run([sys.executable,'-m','scfs',str(path)+'missing','--json'],capture_output=True,text=True)
            self.assertEqual(process.returncode,2)

if __name__ == '__main__':
    unittest.main()

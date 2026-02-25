#!/usr/bin/env python3
"""Credential Scanner V2 - 단위 테스트"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from scanner import (
    Finding, Rule, BaselineManager, EntropyAnalyzer,
    CredentialScannerV2, EXIT_CLEAN, EXIT_FINDINGS, SEVERITY_ORDER
)


class TestFinding(unittest.TestCase):
    def setUp(self):
        self.finding = Finding(
            rule_id='aws_access_key', rule_name='AWS 액세스 키',
            severity='CRITICAL', file_path='/test/file.py',
            line_number=10, matched_text='AKIA00TESTHOUND00FAKE',  # credhound:ignore
            confidence='HIGH'
        )

    def test_to_dict_masked(self):
        d = self.finding.to_dict(mask=True)
        self.assertEqual(d['matched_text'], 'AKIA****FAKE')  # credhound:ignore

    def test_to_dict_unmasked(self):
        d = self.finding.to_dict(mask=False)
        self.assertEqual(d['matched_text'], 'AKIA00TESTHOUND00FAKE')  # credhound:ignore

    def test_mask_short_text(self):
        self.assertEqual(Finding._mask_text('abc'), 'abc****')
        self.assertEqual(Finding._mask_text('short12'), 'sho****')

    def test_mask_long_text(self):
        self.assertEqual(Finding._mask_text('AKIA00TESTHOUND00FAKE'), 'AKIA****FAKE')  # credhound:ignore

    def test_get_hash(self):
        h = self.finding.get_hash()
        self.assertEqual(len(h), 16)
        # 같은 입력이면 같은 해시
        self.assertEqual(h, self.finding.get_hash())

    def test_to_dict_excludes_none(self):
        d = self.finding.to_dict(mask=False)
        self.assertNotIn('entropy', d)
        self.assertNotIn('is_base64', d)


class TestRule(unittest.TestCase):
    def test_value_pattern_match(self):
        rule = Rule({
            'id': 'aws_access_key', 'name': 'AWS Key', 'severity': 'CRITICAL',
            'value_patterns': [{'name': 'AKIA', 'pattern': 'AKIA[0-9A-Z]{16}'}]
        })
        self.assertEqual(rule.check_value_patterns('AKIA00TESTHOUND00FAKE'), 'AKIA')  # credhound:ignore
        self.assertIsNone(rule.check_value_patterns('not_a_key'))  # credhound:ignore

    def test_value_exclusion(self):
        rule = Rule({
            'id': 'test', 'name': 'Test',
            'value_patterns': [{'name': 'key', 'pattern': 'AKIA[0-9A-Z]{16}'}],
            'value_exclusions': ['AKIAIOSFODNN7EXAMPLE']
        })
        self.assertTrue(rule.is_excluded_value('AKIAIOSFODNN7EXAMPLE'))  # credhound:ignore
        self.assertFalse(rule.is_excluded_value('AKIA00TESTHOUND00FAKE'))  # credhound:ignore

    def test_invalid_regex(self):
        # 잘못된 정규식이 에러 없이 건너뛰어지는지
        rule = Rule({
            'id': 'test', 'name': 'Test',
            'value_patterns': [{'name': 'bad', 'pattern': '[invalid'}],
            'variable_patterns': ['[invalid']
        })
        self.assertEqual(len(rule.value_patterns), 0)
        self.assertEqual(len(rule.variable_patterns), 0)


class TestEntropyAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = EntropyAnalyzer({
            'enabled': True, 'threshold': 4.5,
            'min_length': 20, 'max_length': 120,
            'short_string_threshold': 5.5, 'long_string_threshold': 5.2
        })

    def test_calculate_entropy(self):
        # 반복 문자 = 낮은 엔트로피
        self.assertLess(self.analyzer.calculate_entropy('aaaaaaaaaa'), 1.0)
        # 랜덤 문자 = 높은 엔트로피
        self.assertGreater(self.analyzer.calculate_entropy('aB3$xY9!kL2@mN5#'), 3.0)

    def test_empty_string(self):
        self.assertEqual(self.analyzer.calculate_entropy(''), 0.0)

    def test_high_entropy_detection(self):
        # 짧은 문자열 제외
        is_high, _ = self.analyzer.is_high_entropy('short')
        self.assertFalse(is_high)
        # Git SHA 제외
        is_high, _ = self.analyzer.is_high_entropy('a' * 40)
        self.assertFalse(is_high)

    def test_is_base64(self):
        self.assertTrue(self.analyzer.is_base64('SGVsbG8gV29ybGQ='))
        self.assertFalse(self.analyzer.is_base64('not base64!!!'))

    def test_path_excluded(self):
        # 경로 문자 포함 시 제외
        is_high, _ = self.analyzer.is_high_entropy('/usr/local/bin/something/long/path')
        self.assertFalse(is_high)


class TestBaselineManager(unittest.TestCase):
    def test_load_missing_file(self):
        bm = BaselineManager('/nonexistent/path.json')
        self.assertEqual(bm.baseline, {'exclusions': [], 'patterns': []})

    def test_add_and_check_exclusion(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
            json.dump({'exclusions': [], 'patterns': []}, f)
            path = f.name
        try:
            bm = BaselineManager(path)
            finding = Finding(
                rule_id='test', rule_name='Test', severity='HIGH',
                file_path='/test.py', line_number=1, matched_text='secret123'
            )
            self.assertFalse(bm.is_excluded(finding))
            bm.add_exclusion(finding, 'test reason')
            self.assertTrue(bm.is_excluded(finding))
            # 저장된 텍스트가 마스킹되어 있는지
            self.assertIn('****', bm.baseline['exclusions'][0]['text'])
        finally:
            os.unlink(path)


class TestCredentialScannerV2(unittest.TestCase):
    def setUp(self):
        script_dir = Path(__file__).parent
        self.scanner = CredentialScannerV2(
            config_path=str(script_dir / 'config.yaml'),
            rules_path=str(script_dir / 'rules.yaml')
        )

    def test_rules_loaded(self):
        self.assertGreaterEqual(len(self.scanner.rules), 25)

    def test_exit_code_clean(self):
        self.assertEqual(self.scanner.get_exit_code([], 'LOW'), EXIT_CLEAN)

    def test_exit_code_findings(self):
        f = Finding(rule_id='t', rule_name='T', severity='HIGH',
                    file_path='/t', line_number=1, matched_text='x')
        self.assertEqual(self.scanner.get_exit_code([f], 'LOW'), EXIT_FINDINGS)

    def test_severity_filter(self):
        findings = [
            Finding(rule_id='t', rule_name='T', severity='CRITICAL', file_path='/t', line_number=1, matched_text='a'),
            Finding(rule_id='t', rule_name='T', severity='LOW', file_path='/t', line_number=2, matched_text='b'),
        ]
        filtered = self.scanner.filter_by_severity(findings, 'HIGH')
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].severity, 'CRITICAL')

    def test_export_json(self):
        f = Finding(rule_id='test', rule_name='Test', severity='HIGH',
                    file_path='/t', line_number=1, matched_text='AKIA00TESTHOUND00FAKE')  # credhound:ignore
        result = json.loads(self.scanner.export_json([f], mask=True))
        self.assertEqual(result['tool']['name'], 'credhound')
        self.assertTrue(result['masked'])
        self.assertIn('****', result['findings'][0]['matched_text'])  # credhound:ignore

    def test_export_json_unmasked(self):
        f = Finding(rule_id='test', rule_name='Test', severity='HIGH',
                    file_path='/t', line_number=1, matched_text='AKIA00TESTHOUND00FAKE')  # credhound:ignore
        result = json.loads(self.scanner.export_json([f], mask=False))
        self.assertFalse(result['masked'])
        self.assertEqual(result['findings'][0]['matched_text'], 'AKIA00TESTHOUND00FAKE')  # credhound:ignore

    def test_export_sarif(self):
        f = Finding(rule_id='test', rule_name='Test', severity='HIGH',
                    file_path='/t', line_number=1, matched_text='secret')
        result = json.loads(self.scanner.export_sarif([f]))
        self.assertEqual(result['version'], '2.1.0')
        self.assertEqual(len(result['runs'][0]['results']), 1)

    def test_export_html(self):
        f = Finding(rule_id='test', rule_name='Test', severity='HIGH',
                    file_path='/t', line_number=1, matched_text='AKIA00TESTHOUND00FAKE')  # credhound:ignore
        html = self.scanner.export_html([f], mask=True)
        self.assertIn('CredHound Report', html)
        self.assertIn('AKIA****FAKE', html)  # credhound:ignore
        self.assertNotIn('AKIA00TESTHOUND00FAKE', html)  # credhound:ignore

    def test_group_findings(self):
        findings = [
            Finding(rule_id='t', rule_name='T', severity='HIGH', file_path='/a.py', line_number=1, matched_text='KEY123'),
            Finding(rule_id='t', rule_name='T', severity='HIGH', file_path='/b.py', line_number=5, matched_text='KEY123'),
        ]
        groups = self.scanner.group_findings(findings)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups['KEY123']['locations']), 2)

    def test_scan_file_content(self):
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write('AWS_KEY = "AKIA00TESTHOUND00FAKE"\n')  # credhound:ignore
            path = f.name
        try:
            findings, error = self.scanner.scan_file_content(Path(path))
            self.assertIsNone(error)
            aws_findings = [f for f in findings if f.rule_id == 'aws_access_key']
            self.assertGreaterEqual(len(aws_findings), 1)
        finally:
            os.unlink(path)

    def test_scan_cache(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            path = f.name
        try:
            cache = self.scanner.load_cache(path)
            self.assertEqual(cache, {})
            cache['/test.py'] = 12345.0
            self.scanner.save_cache(cache, path)
            loaded = self.scanner.load_cache(path)
            self.assertEqual(loaded['/test.py'], 12345.0)
        finally:
            os.unlink(path)

    def test_symlink_skipped(self):
        """symlink 파일이 스캔에서 제외되는지 확인"""
        with tempfile.TemporaryDirectory() as tmpdir:
            real_file = Path(tmpdir) / 'real.py'
            real_file.write_text('AWS_KEY = "AKIA00TESTHOUND00FAKE"\n')  # credhound:ignore
            link_file = Path(tmpdir) / 'link.py'
            link_file.symlink_to(real_file)
            findings, error = self.scanner.scan_file_content(link_file)
            self.assertEqual(len(findings), 0)
            self.assertIsNone(error)

    def test_html_xss_escaped(self):
        """파일 경로에 HTML 특수문자가 있을 때 이스케이프 확인"""
        f = Finding(rule_id='test', rule_name='<script>alert(1)</script>',
                    severity='HIGH', file_path='/path/<img onerror=alert(1)>',
                    line_number=1, matched_text='secret_value')
        html_output = self.scanner.export_html([f], mask=True)
        self.assertNotIn('<script>alert(1)</script>', html_output)
        self.assertIn('&lt;script&gt;', html_output)

    def test_baseline_pattern_caching(self):
        """베이스라인 패턴 캐싱 확인"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
            json.dump({'exclusions': [], 'patterns': ['secret.*']}, f)
            path = f.name
        try:
            from scanner import BaselineManager
            bm = BaselineManager(path)
            finding = Finding(rule_id='t', rule_name='T', severity='HIGH',
                            file_path='/t', line_number=1, matched_text='secret123')
            self.assertTrue(bm.is_excluded(finding))
            # 캐시된 패턴 확인
            self.assertIn('secret.*', bm._compiled_patterns)
        finally:
            os.unlink(path)

    def test_merge_config(self):
        """설정 병합 테스트"""
        self.scanner.config = {'exclude_dirs': ['a'], 'scan': {'max_workers': 4}}
        self.scanner._merge_config({'exclude_dirs': ['b'], 'scan': {'max_workers': 8}})
        self.assertIn('a', self.scanner.config['exclude_dirs'])
        self.assertIn('b', self.scanner.config['exclude_dirs'])
        self.assertEqual(self.scanner.config['scan']['max_workers'], 8)

    def test_sarif_compliance(self):
        """SARIF 2.1.0 준수 검증 — fingerprints, CWE, remediation, schema"""
        f = Finding(rule_id='aws_access_key', rule_name='AWS 액세스 키',
                    severity='CRITICAL', file_path='/test.py',
                    line_number=10, matched_text='AKIA00TESTHOUND00FAKE')  # credhound:ignore
        sarif = json.loads(self.scanner.export_sarif([f]))
        run = sarif['runs'][0]
        rule = run['tool']['driver']['rules'][0]
        result = run['results'][0]
        # schema URI (errata01)
        self.assertIn('errata01', sarif['$schema'])
        # fingerprints
        self.assertIn('fingerprints', result)
        self.assertIn('credhound/v1', result['fingerprints'])
        # CWE relationship
        self.assertTrue(len(rule.get('relationships', [])) > 0)
        self.assertEqual(rule['relationships'][0]['target']['id'], 'CWE-798')
        # helpUri
        self.assertIn('cwe.mitre.org', rule['helpUri'])
        # remediation help text
        self.assertIn('text', rule.get('help', {}))

    def test_inline_allowlist(self):
        """인라인 허용목록 (credhound:ignore) 테스트"""
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write('AWS_KEY = "AKIA00TESTHOUND00FAKE"  # credhound:ignore\n')
            f.write('AWS_KEY2 = "AKIA00TESTHOUND00FAKE"\n')  # credhound:ignore
            path = f.name
        try:
            findings, error = self.scanner.scan_file_content(Path(path))
            self.assertIsNone(error)
            # 1번 라인은 ignore, 2번 라인만 탐지
            aws = [x for x in findings if x.rule_id == 'aws_access_key']
            self.assertEqual(len(aws), 1)
            self.assertEqual(aws[0].line_number, 2)
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()

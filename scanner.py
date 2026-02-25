#!/usr/bin/env python3
"""
Credential Scanner v2 - 개선된 버전
업계 표준 준수: SARIF 2.1.0, CI/CD 연동, 병렬 처리, Pre-commit 훅
"""
import os
import re
import sys
import math
import json
import time
import base64
import yaml
import hashlib
import signal
import logging
import subprocess
import threading
from pathlib import Path
from typing import List, Dict, Set, Any, Optional, Tuple
from collections import Counter
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger('credhound')


# Exit codes (업계 표준)
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

# Severity 순서
SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

# CWE 매핑 (업계 표준)
CWE_MAP = {
    'aws_access_key': 'CWE-798', 'aws_session_token': 'CWE-798',
    'private_key': 'CWE-321', 'encryption_key': 'CWE-321',
    'github_token': 'CWE-798', 'slack_token': 'CWE-798',
    'google_api_key': 'CWE-798', 'generic_api_key': 'CWE-798',
    'database_connection': 'CWE-798', 'password_in_code': 'CWE-798',
    'generic_password_url': 'CWE-798', 'jwt_token': 'CWE-522',
    'azure_key': 'CWE-798', 'stripe_key': 'CWE-798',
    'twilio_key': 'CWE-798', 'sendgrid_key': 'CWE-798',
    'hashicorp_vault_token': 'CWE-798', 'gitlab_token': 'CWE-798',
    'shopify_token': 'CWE-798', 'high_entropy': 'CWE-200',
}

# Remediation 가이드
REMEDIATION = {
    'CWE-798': '환경 변수 또는 시크릿 매니저(AWS Secrets Manager, HashiCorp Vault)로 이동하세요. 노출된 credential은 즉시 폐기(revoke)하고 새로 발급하세요.',
    'CWE-321': '암호화 키를 KMS(AWS KMS, GCP KMS) 또는 HSM으로 이동하세요. 하드코딩된 키는 즉시 교체하세요.',
    'CWE-522': '토큰을 안전한 저장소에 보관하고, 전송 시 TLS를 사용하세요. 만료된 토큰은 즉시 폐기하세요.',
    'CWE-200': '민감 정보가 로그, 소스코드, 설정 파일에 노출되지 않도록 하세요. 시크릿 매니저를 사용하세요.',
}


@dataclass
class Finding:
    """탐지 결과를 나타내는 데이터 클래스"""
    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    line_number: int
    matched_text: str
    context: Optional[str] = None
    variable_name: Optional[str] = None
    entropy: Optional[float] = None
    is_base64: Optional[bool] = None
    confidence: str = "MEDIUM"  # HIGH, MEDIUM, LOW

    def to_dict(self, mask: bool = True) -> Dict:
        """딕셔너리로 변환"""
        d = {k: v for k, v in asdict(self).items() if v is not None}
        if mask and 'matched_text' in d:
            d['matched_text'] = self._mask_text(d['matched_text'])
        return d

    @staticmethod
    def _mask_text(text: str) -> str:
        """credential 값을 마스킹 (앞 4자 + **** + 뒤 4자)"""
        if len(text) <= 12:
            return text[:3] + '****'
        return text[:4] + '****' + text[-4:]

    def get_hash(self) -> str:
        """Finding의 고유 해시 생성 (baseline용)"""
        key = f"{self.file_path}:{self.line_number}:{self.matched_text}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


def _regex_safe_search(pattern: re.Pattern, text: str, timeout_chars: int = 10_000_000) -> Optional[re.Match]:
    """ReDoS 방어: 입력 길이를 제한하여 catastrophic backtracking 방지"""
    if len(text) > timeout_chars:
        text = text[:timeout_chars]
    return pattern.search(text)


def _regex_safe_finditer(pattern: re.Pattern, text: str, timeout_chars: int = 10_000_000):
    """ReDoS 방어: finditer에 입력 길이 제한 적용"""
    if len(text) > timeout_chars:
        text = text[:timeout_chars]
    return pattern.finditer(text)


class Rule:
    """탐지 규칙 클래스"""

    def __init__(self, rule_config: Dict[str, Any]):
        self.id = rule_config['id']
        self.name = rule_config['name']
        self.severity = rule_config.get('severity', 'MEDIUM')
        self.description = rule_config.get('description', '')
        self.confidence = rule_config.get('confidence', 'HIGH')

        # 변수명 패턴
        self.variable_patterns = []
        for pattern in rule_config.get('variable_patterns', []):
            try:
                self.variable_patterns.append(re.compile(pattern))
            except re.error as e:
                logger.warning(f"잘못된 변수 패턴: {pattern} - {e}")

        # 값 패턴
        self.value_patterns = []
        for pattern_def in rule_config.get('value_patterns', []):
            try:
                self.value_patterns.append({
                    'name': pattern_def['name'],
                    'pattern': re.compile(pattern_def['pattern'])
                })
            except re.error as e:
                logger.warning(f"잘못된 값 패턴: {pattern_def.get('pattern')} - {e}")

        # 제외 패턴
        self.value_exclusions = []
        for pattern in rule_config.get('value_exclusions', []):
            try:
                self.value_exclusions.append(re.compile(pattern))
            except re.error:
                pass

    def is_variable_match(self, var_name: str) -> bool:
        if not var_name:
            return False
        return any(_regex_safe_search(p, var_name) for p in self.variable_patterns)

    def is_excluded_value(self, value: str) -> bool:
        return any(_regex_safe_search(p, value) for p in self.value_exclusions)

    def check_value_patterns(self, value: str) -> Optional[str]:
        for pattern_def in self.value_patterns:
            if _regex_safe_search(pattern_def['pattern'], value):
                return pattern_def['name']
        return None


class BaselineManager:
    """False positive 관리 클래스"""

    def __init__(self, baseline_file: str):
        self.baseline_file = baseline_file
        self.baseline = self._load_baseline()
        self._compiled_patterns: Dict[str, re.Pattern] = {}

    def _load_baseline(self) -> Dict:
        if not os.path.exists(self.baseline_file):
            return {'exclusions': [], 'patterns': []}
        try:
            with open(self.baseline_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Baseline 파일 로드 실패: {e}")
            return {'exclusions': [], 'patterns': []}

    def save_baseline(self) -> bool:
        try:
            with open(self.baseline_file, 'w', encoding='utf-8') as f:
                json.dump(self.baseline, f, indent=2, ensure_ascii=False)
            return True
        except IOError as e:
            logger.error(f"Baseline 저장 실패: {e}")
            return False

    def is_excluded(self, finding: Finding) -> bool:
        finding_hash = finding.get_hash()
        for exclusion in self.baseline.get('exclusions', []):
            if exclusion.get('hash') == finding_hash:
                return True
        for pattern_str in self.baseline.get('patterns', []):
            try:
                compiled = self._compiled_patterns.get(pattern_str)
                if compiled is None:
                    compiled = re.compile(pattern_str)
                    self._compiled_patterns[pattern_str] = compiled
                if compiled.search(finding.matched_text):
                    return True
            except re.error:
                pass
        return False

    def add_exclusion(self, finding: Finding, reason: str = "False positive"):
        self.baseline.setdefault('exclusions', []).append({
            'hash': finding.get_hash(),
            'file': finding.file_path,
            'line': finding.line_number,
            'text': Finding._mask_text(finding.matched_text[:50]),
            'reason': reason,
            'added_at': datetime.now().isoformat()
        })

    def add_pattern_exclusion(self, pattern: str, reason: str = "Pattern exclusion"):
        self.baseline.setdefault('patterns', []).append(pattern)


class EntropyAnalyzer:
    """엔트로피 기반 분석기"""

    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get('enabled', True)
        self.threshold = config.get('threshold', 4.5)
        self.min_length = config.get('min_length', 20)
        self.max_length = config.get('max_length', 120)
        self.short_threshold = config.get('short_string_threshold', 5.5)
        self.long_threshold = config.get('long_string_threshold', 5.2)

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def is_high_entropy(self, text: str) -> Tuple[bool, float]:
        if not text or len(text) < self.min_length or len(text) > self.max_length:
            return False, 0.0
        if '/' in text or '\\' in text:
            return False, 0.0
        if text.startswith(('sha512-', 'sha256-')):
            return False, 0.0
        if re.match(r'^[0-9a-fA-F]{40}$', text):
            return False, 0.0
        if len(set(text)) < 5:
            return False, 0.0

        entropy = self.calculate_entropy(text)
        if 20 <= len(text) <= 39:
            threshold = self.short_threshold
        elif len(text) >= 40:
            threshold = self.long_threshold
        else:
            threshold = self.threshold
        return entropy >= threshold, entropy

    def is_base64(self, text: str) -> bool:
        try:
            if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', text):
                return False
            decoded = base64.b64decode(text, validate=True)
            image_sigs = [b'<svg', b'<?xml', b'\x89PNG', b'\xff\xd8\xff',
                         b'GIF87a', b'GIF89a', b'RIFF', b'BM']
            for sig in image_sigs:
                if decoded.startswith(sig):
                    return False
            return len(decoded) > 0
        except Exception:
            return False


_ENTROPY_TOKEN_PATTERN = re.compile(r'[A-Za-z0-9+/=_-]{20,}')
_ENTROPY_FP_PATTERNS = [
    re.compile(r'^[a-z]+$'), re.compile(r'^[A-Z]+$'), re.compile(r'^[0-9]+$'),
    re.compile(r'^abcdefghijklmnopqrstuvwxyz', re.IGNORECASE),
    re.compile(r'^ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
    re.compile(r'EXAMPLE', re.IGNORECASE), re.compile(r'^useandom-'),
    re.compile(r'^123456789ABC'), re.compile(r'^eyJsYXN0RXZhbHVhdGVkS2V5'),
    re.compile(r'^nextToken='), re.compile(r'^0123456789'),
]


class CredentialScannerV2:
    """개선된 Credential Scanner - 업계 표준 준수"""

    VERSION = "2.8.7"
    TOOL_NAME = "credhound"

    def __init__(self, config_path: str = 'config.yaml', rules_path: str = 'rules.yaml'):
        self.config = self._load_config(config_path)
        # 로컬 설정 병합 (config.local.yaml)
        local_config_path = config_path.replace('.yaml', '.local.yaml')
        local_config = self._load_config(local_config_path)
        if local_config:
            self._merge_config(local_config)
        self.rules_config = self._load_config(rules_path)
        self._validate_config()
        self.rules = [Rule(rc) for rc in self.rules_config.get('rules', [])]
        self.file_patterns = self._init_file_patterns()
        self._exclude_patterns: List[re.Pattern] = []
        self._exclude_dirs_set = set(self.config.get('exclude_dirs', []))
        for p in self.config.get('exclude_patterns', []):
            try:
                self._exclude_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                logger.warning(f"잘못된 제외 패턴: {p}")
        self.entropy_analyzer = EntropyAnalyzer(self.config.get('entropy', {}))
        baseline_file = self.config.get('baseline_file', '.credscan-baseline.json')
        self.baseline_manager = BaselineManager(baseline_file)
        self._lock = threading.Lock()
        self.stats = {
            'files_found': 0, 'files_scanned': 0, 'findings_count': 0,
            'excluded_count': 0, 'files_failed': 0, 'files_excluded': 0,
            'scan_time': 0.0
        }

    def _load_config(self, path: str) -> Dict:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            return {}
        except (yaml.YAMLError, IOError) as e:
            logger.error(f"설정 파일 로드 실패: {e}")
            return {}

    def _merge_config(self, local: Dict) -> None:
        """로컬 설정을 글로벌 설정에 병합 (리스트는 추가, 값은 덮어쓰기)"""
        for key, value in local.items():
            if isinstance(value, list) and isinstance(self.config.get(key), list):
                self.config[key] = self.config[key] + value
            elif isinstance(value, dict) and isinstance(self.config.get(key), dict):
                self.config[key].update(value)
            else:
                self.config[key] = value

    def _validate_config(self) -> None:
        """설정값 검증"""
        scan = self.config.get('scan', {})
        max_size = scan.get('max_file_size', 10485760)
        if not isinstance(max_size, int) or max_size <= 0 or max_size > 104857600:
            logger.warning(f"잘못된 max_file_size: {max_size} → 기본값 10MB 사용 (상한: 100MB)")
            self.config.setdefault('scan', {})['max_file_size'] = 10485760

        workers = scan.get('max_workers', 4)
        if not isinstance(workers, int) or workers < 0:
            logger.warning(f"잘못된 max_workers: {workers} → 기본값 4 사용")
            self.config.setdefault('scan', {})['max_workers'] = 4

        entropy = self.config.get('entropy', {})
        threshold = entropy.get('threshold', 4.5)
        if not isinstance(threshold, (int, float)) or threshold <= 0 or threshold > 8:
            logger.warning(f"잘못된 entropy threshold: {threshold} → 기본값 4.5 사용")
            self.config.setdefault('entropy', {})['threshold'] = 4.5

        rules = self.rules_config.get('rules', [])
        for i, rule in enumerate(rules):
            if 'id' not in rule or 'name' not in rule:
                logger.warning(f"규칙 #{i+1}에 id 또는 name이 없습니다 — 건너뜀")
            if 'value_patterns' not in rule and 'variable_patterns' not in rule:
                logger.warning(f"규칙 '{rule.get('id', '?')}'에 패턴이 정의되지 않았습니다")

    def _init_file_patterns(self) -> Dict[str, Dict]:
        patterns = {}
        for pc in self.rules_config.get('file_patterns', []):
            category = pc['category']
            patterns[category] = {
                'severity': pc.get('severity', 'MEDIUM'),
                'patterns': [re.compile(p) for p in pc['patterns']]
            }
        return patterns

    def should_exclude_file(self, filepath: str) -> bool:
        file_str = str(filepath).lower()
        for compiled in self._exclude_patterns:
            if compiled.search(file_str):
                return True
        return False

    def scan_file_patterns(self, scan_path: str) -> Dict[str, List[Dict]]:
        results = {}
        for category, pattern_info in self.file_patterns.items():
            results[category] = []
            for root, dirs, files in os.walk(scan_path, followlinks=False):
                dirs[:] = [d for d in dirs if d not in self._exclude_dirs_set]
                for file in files:
                    file_path = Path(root) / file
                    if not file_path.is_symlink():
                        relative_path = str(file_path.relative_to(scan_path))
                        for pattern in pattern_info['patterns']:
                            if pattern.search(relative_path):
                                try:
                                    stat = file_path.stat()
                                    results[category].append({
                                        'path': str(file_path),
                                        'size': stat.st_size,
                                        'modified': stat.st_mtime,
                                        'severity': pattern_info['severity']
                                    })
                                except (PermissionError, OSError):
                                    pass
        return results

    def _validate_path(self, file_path: Path, scan_root: Optional[Path] = None) -> bool:
        """Path Traversal 방어: 파일이 스캔 루트 내에 있는지 검증"""
        try:
            resolved = file_path.resolve()
            if scan_root is not None:
                root_resolved = scan_root.resolve()
                if not str(resolved).startswith(str(root_resolved) + os.sep) and resolved != root_resolved:
                    logger.warning(f"경로 검증 실패 (스캔 루트 외부): {file_path}")
                    return False
            return True
        except (OSError, ValueError):
            return False

    def scan_file_content(self, file_path: Path, scan_root: Optional[Path] = None) -> Tuple[List[Finding], Optional[str]]:
        """파일 내용 스캔 (단일 파일)"""
        findings = []
        if file_path.is_symlink():
            return findings, None
        if not self._validate_path(file_path, scan_root):
            return findings, None
        if self.should_exclude_file(file_path):
            with self._lock:
                self.stats['files_excluded'] += 1
            return findings, None

        scannable_exts = self.config.get('scannable_extensions', [])
        suffix = file_path.suffix.lower()
        filename = file_path.name.lower()
        if suffix:
            if suffix not in scannable_exts:
                with self._lock:
                    self.stats['files_excluded'] += 1
                return findings, None
        else:
            if not any(filename == ext.lstrip('.') or filename == ext for ext in scannable_exts):
                with self._lock:
                    self.stats['files_excluded'] += 1
                return findings, None

        max_file_size = self.config.get('scan', {}).get('max_file_size', 10485760)
        try:
            # TOCTOU 방지: stat으로 먼저 크기 확인
            try:
                file_size = file_path.stat().st_size
                if file_size > max_file_size:
                    with self._lock:
                        self.stats['files_excluded'] += 1
                    return findings, None
            except OSError:
                pass  # stat 실패 시 읽기 시도
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(max_file_size + 1)
                if len(content) > max_file_size:
                    with self._lock:
                        self.stats['files_excluded'] += 1
                    return findings, None
        except UnicodeDecodeError:
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    content = f.read(max_file_size + 1)
                    if len(content) > max_file_size:
                        with self._lock:
                            self.stats['files_excluded'] += 1
                        return findings, None
            except (PermissionError, OSError) as e:
                return findings, f"파일 읽기 실패: {e}"
        except PermissionError:
            return findings, "권한 없음"
        except OSError as e:
            return findings, f"파일 읽기 실패: {e}"

        lines = content.split('\n')
        allowlisted_lines = set()
        for i, line in enumerate(lines, 1):
            if 'credhound:ignore' in line or 'pragma: allowlist secret' in line:
                allowlisted_lines.add(i)

        for rule in self.rules:
            for pattern_def in rule.value_patterns:
                for match in _regex_safe_finditer(pattern_def['pattern'], content):
                    matched_text = match.group(0)
                    if not rule.is_excluded_value(matched_text):
                        line_num = content[:match.start()].count('\n') + 1
                        if line_num in allowlisted_lines:
                            continue
                        findings.append(Finding(
                            rule_id=rule.id, rule_name=rule.name,
                            severity=rule.severity, file_path=str(file_path),
                            line_number=line_num, matched_text=matched_text[:100],
                            context=pattern_def['name'], confidence=rule.confidence
                        ))

        if self.entropy_analyzer.enabled:
            findings.extend(self._analyze_entropy(file_path, content))

        return findings, None

    def _analyze_entropy(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if file_path.suffix.lower() in {'.pem', '.crt', '.cer'}:
            return findings

        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for match in _ENTROPY_TOKEN_PATTERN.finditer(line):
                text = match.group(0)
                if any(fp.search(text) for fp in _ENTROPY_FP_PATTERNS):
                    continue
                is_high, entropy = self.entropy_analyzer.is_high_entropy(text)
                if is_high:
                    findings.append(Finding(
                        rule_id='high_entropy',
                        rule_name='높은 엔트로피 문자열 (잠재적 키)',
                        severity='LOW', file_path=str(file_path),
                        line_number=line_num, matched_text=text[:100],
                        entropy=round(entropy, 2),
                        is_base64=self.entropy_analyzer.is_base64(text),
                        context='엔트로피 분석', confidence='LOW'
                    ))
        return findings

    # ── 스캔 실행 ──────────────────────────────────────────────

    def _collect_files(self, scan_path: str) -> List[Path]:
        files_to_scan = []
        exclude_dirs = self._exclude_dirs_set
        for root, dirs, files in os.walk(scan_path, followlinks=False):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                fp = Path(root) / file
                if not fp.is_symlink():
                    files_to_scan.append(fp)
        return files_to_scan

    def scan_content_sequential(self, scan_path: str, progress_callback=None, debug=False) -> List[Finding]:
        """순차 내용 스캔"""
        start_time = time.time()
        all_findings = []
        failed_files = []
        files_to_scan = self._collect_files(scan_path)
        self.stats['files_found'] = len(files_to_scan)
        seen = set()
        scan_root = Path(scan_path).resolve()

        for idx, file_path in enumerate(files_to_scan, 1):
            try:
                findings, error = self.scan_file_content(file_path, scan_root=scan_root)
                if error:
                    self.stats['files_failed'] += 1
                    failed_files.append((str(file_path), error))
                else:
                    self.stats['files_scanned'] += 1
                for f in findings:
                    key = f"{f.file_path}:{f.line_number}:{f.matched_text}"
                    if key in seen:
                        continue
                    seen.add(key)
                    if self.baseline_manager.is_excluded(f):
                        self.stats['excluded_count'] += 1
                    else:
                        all_findings.append(f)
                if progress_callback and idx % 10 == 0:
                    progress_callback(idx, len(files_to_scan))
            except KeyboardInterrupt:
                raise
            except (OSError, ValueError) as e:
                self.stats['files_failed'] += 1
                failed_files.append((str(file_path), str(e)))

        self.stats['scan_time'] = time.time() - start_time
        self.stats['findings_count'] = len(all_findings)
        self.stats['failed_files_list'] = failed_files[:10]
        return all_findings

    def scan_content_parallel(self, scan_path: str, progress_callback=None, debug=False) -> List[Finding]:
        """병렬 내용 스캔 (ThreadPoolExecutor)"""
        start_time = time.time()
        all_findings = []
        failed_files = []
        files_to_scan = self._collect_files(scan_path)
        self.stats['files_found'] = len(files_to_scan)
        seen = set()
        max_workers = self.config.get('scan', {}).get('max_workers', 4) or os.cpu_count()
        completed = 0
        scan_root = Path(scan_path).resolve()
        executor = ThreadPoolExecutor(max_workers=max_workers)
        futures = {}

        try:
            futures = {executor.submit(self.scan_file_content, fp, scan_root): fp for fp in files_to_scan}
            for future in as_completed(futures):
                completed += 1
                try:
                    findings, error = future.result()
                    if error:
                        with self._lock:
                            self.stats['files_failed'] += 1
                            failed_files.append((str(futures[future]), error))
                    else:
                        with self._lock:
                            self.stats['files_scanned'] += 1
                    for f in findings:
                        key = f"{f.file_path}:{f.line_number}:{f.matched_text}"
                        with self._lock:
                            if key in seen:
                                continue
                            seen.add(key)
                            if self.baseline_manager.is_excluded(f):
                                self.stats['excluded_count'] += 1
                            else:
                                all_findings.append(f)
                    if progress_callback and completed % 10 == 0:
                        progress_callback(completed, len(files_to_scan))
                except KeyboardInterrupt:
                    raise
                except (OSError, ValueError) as e:
                    with self._lock:
                        self.stats['files_failed'] += 1
                        failed_files.append((str(futures[future]), str(e)))
        except KeyboardInterrupt:
            for f in futures:
                f.cancel()
            raise
        finally:
            executor.shutdown(wait=True)

        self.stats['scan_time'] = time.time() - start_time
        self.stats['findings_count'] = len(all_findings)
        self.stats['failed_files_list'] = failed_files[:10]
        return all_findings

    def scan(self, scan_path: str, progress_callback=None, debug=False, parallel=False) -> Tuple[Dict, List[Finding]]:
        """전체 스캔 실행"""
        file_pattern_results = self.scan_file_patterns(scan_path)
        if parallel:
            content_findings = self.scan_content_parallel(scan_path, progress_callback, debug)
        else:
            content_findings = self.scan_content_sequential(scan_path, progress_callback, debug)
        return file_pattern_results, content_findings

    # ── Git 연동 ───────────────────────────────────────────────

    def scan_git_diff(self, repo_path: str, progress_callback=None) -> Tuple[Dict, List[Finding]]:
        """Git 변경 파일만 스캔 (incremental)"""
        try:
            result = subprocess.run(
                ['git', 'diff', '--name-only', '--cached', 'HEAD'],
                capture_output=True, text=True, cwd=repo_path
            )
            staged = result.stdout.strip().splitlines() if result.returncode == 0 else []
            result2 = subprocess.run(
                ['git', 'diff', '--name-only'],
                capture_output=True, text=True, cwd=repo_path
            )
            unstaged = result2.stdout.strip().splitlines() if result2.returncode == 0 else []
            changed = list(set(staged + unstaged))
        except FileNotFoundError:
            logger.warning("git이 설치되어 있지 않습니다.")
            return {}, []

        if not changed:
            return {}, []

        start_time = time.time()
        all_findings = []
        seen = set()
        self.stats['files_found'] = len(changed)

        for idx, rel_path in enumerate(changed, 1):
            fp = Path(repo_path) / rel_path
            if not fp.exists():
                continue
            findings, error = self.scan_file_content(fp)
            if error:
                self.stats['files_failed'] += 1
            else:
                self.stats['files_scanned'] += 1
            for f in findings:
                key = f"{f.file_path}:{f.line_number}:{f.matched_text}"
                if key not in seen:
                    seen.add(key)
                    if self.baseline_manager.is_excluded(f):
                        self.stats['excluded_count'] += 1
                    else:
                        all_findings.append(f)
            if progress_callback and idx % 5 == 0:
                progress_callback(idx, len(changed))

        self.stats['scan_time'] = time.time() - start_time
        self.stats['findings_count'] = len(all_findings)
        return {}, all_findings

    def generate_pre_commit_hook(self, repo_path: str = '.') -> str:
        """Pre-commit 훅 생성 및 설치"""
        hook_path = Path(repo_path) / '.git' / 'hooks' / 'pre-commit'
        hook_content = f"""#!/bin/sh
# CredHound Pre-commit Hook
# 자동 생성됨 - {datetime.now().isoformat()}

echo "🐕 CredHound - Pre-commit 검사 중..."

# credhound CLI가 있으면 사용, 없으면 python3 직접 실행
if command -v credhound >/dev/null 2>&1; then
    credhound --path "$(git rev-parse --show-toplevel)" \\
        --ci --incremental --severity HIGH
else
    python -m main_v2 --path "$(git rev-parse --show-toplevel)" \\
        --ci --incremental --severity HIGH
fi

EXIT_CODE=$?

if [ $EXIT_CODE -eq 1 ]; then
    echo ""
    echo "❌ CRITICAL/HIGH 수준의 credential이 발견되었습니다!"
    echo "커밋이 차단되었습니다. 발견된 credential을 제거하세요."
    echo ""
    echo "False positive인 경우:"
    echo "  credhound --update-baseline"
    echo ""
    exit 1
fi

exit 0
"""
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text(hook_content)
        hook_path.chmod(0o755)
        return str(hook_path)

    # ── 출력 포맷 ──────────────────────────────────────────────

    def export_json(self, findings: List[Finding], file_results: Dict = None, filepath: str = None, mask: bool = True) -> str:
        """JSON 형식으로 내보내기"""
        from reporter import export_json as _export_json
        return _export_json(findings, self.stats.copy(), self.VERSION, file_results, filepath, mask)

    def export_sarif(self, findings: List[Finding], filepath: str = None, mask: bool = True) -> str:
        """SARIF 2.1.0 형식으로 내보내기 (OASIS 표준)"""
        from reporter import export_sarif as _export_sarif
        return _export_sarif(findings, self.VERSION, filepath, mask)

    # ── 유틸리티 ───────────────────────────────────────────────

    def get_exit_code(self, findings: List[Finding], min_severity: str = 'LOW') -> int:
        """CI/CD용 exit code 반환"""
        min_level = SEVERITY_ORDER.get(min_severity, 3)
        for f in findings:
            if SEVERITY_ORDER.get(f.severity, 3) <= min_level:
                return EXIT_FINDINGS
        return EXIT_CLEAN

    def filter_by_severity(self, findings: List[Finding], min_severity: str) -> List[Finding]:
        """최소 심각도 이상만 필터링"""
        min_level = SEVERITY_ORDER.get(min_severity, 3)
        return [f for f in findings if SEVERITY_ORDER.get(f.severity, 3) <= min_level]

    def get_stats(self) -> Dict:
        return self.stats.copy()

    def group_findings(self, findings: List[Finding]) -> Dict[str, Dict]:
        """같은 credential 값을 그룹핑하여 요약"""
        groups = {}
        for f in findings:
            key = f.matched_text
            if key not in groups:
                groups[key] = {
                    'rule_id': f.rule_id, 'rule_name': f.rule_name,
                    'severity': f.severity, 'confidence': f.confidence,
                    'matched_text': f.matched_text, 'locations': []
                }
            groups[key]['locations'].append({
                'file_path': f.file_path, 'line_number': f.line_number
            })
        return groups

    def export_html(self, findings: List[Finding], file_results: Dict = None, filepath: str = None, mask: bool = True) -> str:
        """HTML 리포트 생성"""
        from reporter import export_html as _export_html
        return _export_html(findings, self.stats.copy(), self.VERSION, file_results, filepath, mask)

    def load_cache(self, cache_path: str = '.credscan-cache.json') -> Dict:
        """스캔 캐시 로드 (mtime 기반)"""
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_cache(self, cache: Dict, cache_path: str = '.credscan-cache.json') -> None:
        """스캔 캐시 저장"""
        try:
            with open(cache_path, 'w') as f:
                json.dump(cache, f)
        except IOError as e:
            logger.warning(f"캐시 저장 실패: {e}")

    def is_file_changed(self, file_path: Path, cache: Dict) -> bool:
        """파일이 캐시 이후 변경되었는지 확인"""
        key = str(file_path)
        try:
            mtime = file_path.stat().st_mtime
            return cache.get(key) != mtime
        except OSError:
            return True

# 🐕 CredHound 규정 준수 검증 보고서

> 검증일: 2026-02-20 | 버전: 2.1.0

## 개요

CredHound는 로컬 파일에서 민감한 credential을 탐지하는 보안 도구입니다.
본 문서는 업계 주요 보안 표준 및 규정과의 준수 여부를 검증한 결과입니다.

---

## 1. OWASP Secrets Management Cheat Sheet

**출처**: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

| 요구사항 | CredHound 구현 | 상태 |
|----------|---------------|------|
| 20개 이상 시그니처 매칭 | 30개 탐지 규칙 (rules.yaml) | ✅ |
| 엔트로피 기반 탐지 | Shannon 엔트로피 분석 (EntropyAnalyzer) | ✅ |
| 개발자 수준 탐지 (pre-commit) | `--install-hook` 옵션 | ✅ |
| CI/CD 통합 | `--ci` 모드, exit code 반환 | ✅ |
| False positive 관리 | baseline 파일 (.credscan-baseline.json) | ✅ |
| 파이프라인 출력 시크릿 미노출 | credential 마스킹 기본 ON | ✅ |
| API 키, 패스워드, 개인키, 세션 토큰, 연결 문자열, 플랫폼별 시크릿 탐지 | 전체 커버 | ✅ |
| 노출된 키 폐기 안내 | Remediation 가이드 (SARIF help 필드) | ✅ |
| 인라인 허용목록 | `# credhound:ignore` / `# pragma: allowlist secret` | ✅ |
| 복수 탐지 도구 사용 권장 | README에 안내 권장 | ⚠️ |

---

## 2. SARIF 2.1.0 (OASIS 표준)

**출처**: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

### 필수 필드 준수

| 필수 필드 | CredHound 출력 | 상태 |
|-----------|---------------|------|
| `version`: "2.1.0" | ✅ | ✅ |
| `runs[]` 배열 | ✅ | ✅ |
| `tool.driver.name` | "credhound" | ✅ |
| `results[]` 배열 | ✅ | ✅ |
| `result.message.text` | ✅ | ✅ |
| `level` 유효값 (error/warning/note) | ✅ | ✅ |
| `$schema` URI (errata01) | ✅ 최신 스키마 | ✅ |
| `locations[].physicalLocation` | ✅ | ✅ |
| `artifactLocation.uri` | ✅ | ✅ |
| `region.startLine` | ✅ | ✅ |
| `invocations[].executionSuccessful` | ✅ | ✅ |
| `result.fingerprints` (중복 제거) | SHA-256 기반 해시 | ✅ |
| `rules[].relationships` (CWE 매핑) | CWE-798, CWE-321 | ✅ |
| `rules[].help` (remediation) | 대응 가이드 포함 | ✅ |
| `rules[].helpUri` (CWE 링크) | CWE 상세 페이지 링크 | ✅ |

---

## 3. CWE (Common Weakness Enumeration)

### CWE-798: Use of Hard-coded Credentials
**출처**: https://cwe.mitre.org/data/definitions/798.html

| 탐지 대상 | CredHound 규칙 | 상태 |
|-----------|---------------|------|
| 하드코딩된 패스워드 | `password_in_code` | ✅ |
| 하드코딩된 API 키 | `generic_api_key`, 플랫폼별 규칙 | ✅ |
| URL 내 credential | `generic_password_url` | ✅ |
| DB 연결 문자열 | `database_connection` | ✅ |
| 클라우드 토큰 (AWS, Azure, GCP) | 전용 규칙 | ✅ |
| SARIF에 CWE-798 참조 | `rules[].relationships` | ✅ |

### CWE-321: Use of Hard-coded Cryptographic Key
**출처**: https://cwe.mitre.org/data/definitions/321.html

| 탐지 대상 | CredHound 규칙 | 상태 |
|-----------|---------------|------|
| Private Key (RSA, DSA, EC, PGP) | `private_key` | ✅ |
| 하드코딩된 암호화 키 | `encryption_key` | ✅ |
| SARIF에 CWE-321 참조 | `rules[].relationships` | ✅ |

---

## 4. NIST SP 800-53 Rev 5

**출처**: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

### IA-5 (Authenticator Management)

| 요구사항 | CredHound 구현 | 상태 |
|----------|---------------|------|
| 인증자 콘텐츠 보호 | credential 마스킹 (기본 ON) | ✅ |
| 기본 인증자 변경 감지 | 기본 패스워드 탐지 규칙 | ✅ |
| 무단 공개 방지 | 결과 파일 마스킹, XSS 방지 | ✅ |

### SC-12 (Cryptographic Key Management)

| 요구사항 | CredHound 구현 | 상태 |
|----------|---------------|------|
| 암호화 키 노출 탐지 | `private_key`, `encryption_key` 규칙 | ✅ |
| 키 관리 위반 감지 | 하드코딩된 키 탐지 | ✅ |

---

## 5. PCI DSS v4.0

**출처**: https://www.pcisecuritystandards.org/document_library/

### Requirement 6.2.4 (소프트웨어 보안)

| 요구사항 | CredHound 구현 | 상태 |
|----------|---------------|------|
| 소스코드 내 하드코딩 credential 방지 | 30개 탐지 규칙 | ✅ |
| 자동화된 보안 검사 | CI/CD 모드 (`--ci`) | ✅ |
| Pre-commit 검사 | `--install-hook` | ✅ |

### Requirement 8 (인증 관리)

| 요구사항 | CredHound 구현 | 상태 |
|----------|---------------|------|
| 강력한 인증 메커니즘 검증 | 약한 패스워드 탐지 | ✅ |
| 하드코딩된 credential 방지 | 전체 규칙 세트 | ✅ |

---

## 6. MITRE ATT&CK T1552 (Unsecured Credentials)

**출처**: https://attack.mitre.org/techniques/T1552/

| 하위 기법 | CredHound 커버리지 | 상태 |
|-----------|-------------------|------|
| T1552.001 Credentials In Files | 핵심 기능 — 파일 내 credential 탐지 | ✅ |
| T1552.004 Private Keys | `private_key` 규칙 | ✅ |
| T1552.003 Shell History | 스캔 가능 (확장자 설정) | ⚠️ |
| T1552.002 Credentials in Registry | 범위 외 (로컬 파일 전용) | — |
| T1552.005 Cloud Instance Metadata | 범위 외 | — |

---

## 7. AWS Well-Architected Security Pillar (SEC02)

**출처**: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/

| 요구사항 | CredHound 구현 | 상태 |
|----------|---------------|------|
| 소스코드 시크릿 포함 방지 모니터링 | 핵심 기능 | ✅ |
| AWS Access Key 탐지 | `aws_access_key` (AKIA, ASIA) | ✅ |
| AWS Session Token 탐지 | `aws_session_token` | ✅ |
| 장기→임시 credential 대체 안내 | Remediation 가이드 | ✅ |

---

## 8. detect-secrets (Yelp) 기능 비교

**출처**: https://github.com/Yelp/detect-secrets

| 기능 | detect-secrets | CredHound | 상태 |
|------|---------------|-----------|------|
| Baseline 관리 | `.secrets.baseline` | `.credscan-baseline.json` | ✅ |
| 인라인 허용목록 | `# pragma: allowlist secret` | `# credhound:ignore` + 호환 지원 | ✅ |
| 엔트로피 분석 | ✅ | ✅ | ✅ |
| Pre-commit 훅 | ✅ | ✅ | ✅ |
| 플러그인 아키텍처 | ✅ | YAML 규칙 기반 | ⚠️ |

---

## 9. GitHub Secret Scanning 비교

**출처**: https://docs.github.com/en/code-security/secret-scanning

| 기능 | GitHub | CredHound | 상태 |
|------|--------|-----------|------|
| 제공업체별 패턴 | 500+ | 30개 (주요 패턴 커버) | ⚠️ |
| Push Protection | ✅ | pre-commit 훅 (동등) | ✅ |
| Base64 인코딩 탐지 | ✅ | 엔트로피 분석 | ✅ |
| Validity Check | ✅ | 미지원 | ❌ |

---

## 10. GDPR Article 32 (보안 처리)

| 요구사항 | CredHound 구현 | 상태 |
|----------|---------------|------|
| 개인 데이터 보호를 위한 기술적 조치 | credential 노출 방지 도구 | ✅ |
| 정기적 보안 테스트 | CI/CD 자동 스캔 | ✅ |

---

## 종합 준수율

| 표준 | 충족 | 부분 | 미충족 | 준수율 |
|------|------|------|--------|--------|
| OWASP Secrets Management | 9 | 1 | 0 | 95% |
| SARIF 2.1.0 | 15 | 0 | 0 | 100% |
| CWE-798/321 | 8 | 0 | 0 | 100% |
| NIST SP 800-53 | 5 | 0 | 0 | 100% |
| PCI DSS v4.0 | 5 | 0 | 0 | 100% |
| MITRE ATT&CK T1552 | 2 | 1 | 0 | 83% |
| AWS Well-Architected | 4 | 0 | 0 | 100% |
| detect-secrets 비교 | 4 | 1 | 0 | 90% |
| GitHub Secret Scanning | 3 | 1 | 1 | 70% |
| **전체** | **55** | **4** | **1** | **92%** |

---

## 참고 문서

1. [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
2. [SARIF 2.1.0 (OASIS)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
3. [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / [CWE-321](https://cwe.mitre.org/data/definitions/321.html)
4. [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
5. [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
6. [MITRE ATT&CK T1552](https://attack.mitre.org/techniques/T1552/)
7. [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
8. [detect-secrets (Yelp)](https://github.com/Yelp/detect-secrets)
9. [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
10. [Basak et al. (2023) — Secret Detection Tools 실증 연구](https://ar5iv.labs.arxiv.org/html/2307.00714)
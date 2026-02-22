# 🐕 CredHound

[![PyPI version](https://badge.fury.io/py/credhound.svg)](https://pypi.org/project/credhound/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

로컬 파일에서 민감한 credential을 탐지하는 보안 도구.
OWASP, SARIF 2.1.0, CWE-798/321 등 업계 표준 준수.

## 주요 기능

- **29개 탐지 규칙** — AWS, GitHub, Slack, JWT, DB, 패스워드, Private Key 등
- **엔트로피 분석** — Shannon 엔트로피 기반 미지의 시크릿 탐지
- **다중 출력** — HTML 리포트, JSON, SARIF 2.1.0, 콘솔
- **CI/CD 연동** — exit code, 비대화형 모드, pre-commit 훅
- **병렬 처리** — ThreadPoolExecutor 기반 고속 스캔
- **credential 마스킹** — 결과 파일에 실제 값 노출 방지 (기본 ON)
- **false positive 관리** — baseline 파일 + 인라인 허용목록 (`# credhound:ignore`)
- **CWE 매핑** — SARIF 출력에 CWE-798/321 참조 및 remediation 가이드 포함
- **설정 분리** — 글로벌(config.yaml) + 개인(config.local.yaml) 자동 병합

## 설치

```bash
pip install credhound
```

## 빠른 시작

```bash
# 인터랙티브 모드 (HTML 리포트 자동 생성)
credhound

# 경로 지정
credhound --path ~/project

# 병렬 + HIGH 이상만
credhound --path ~ --parallel --severity HIGH
```

## 출력 형식

```bash
# HTML 리포트 (시각적, 권장)
credhound --path ~ --format html -o report.html

# JSON (프로그래밍적 소비)
credhound --path ~ --format json -o results.json

# SARIF 2.1.0 (GitHub Code Scanning 연동)
credhound --path ~ --format sarif -o results.sarif

# 콘솔 (기본)
credhound --path ~
```

## CI/CD 파이프라인

```bash
# CI 모드 (비대화형, exit code 반환)
credhound --path . --ci --severity HIGH
# exit 0 = clean, exit 1 = findings, exit 2 = error

# SARIF + CI
credhound --path . --ci --format sarif -o results.sarif

# Pre-commit 훅 설치
credhound --install-hook --path .
```

## 인라인 허용목록

False positive를 코드에서 직접 제외할 수 있습니다:

```python
API_KEY = "some_value"  # credhound:ignore
PASSWORD = "test123"    # pragma: allowlist secret
```

## 전체 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--path`, `-p` | 스캔 경로 | 인터랙티브 입력 |
| `--format`, `-f` | 출력 형식 (console/json/sarif/html) | console |
| `--output`, `-o` | 결과 저장 경로 | - |
| `--severity`, `-s` | 최소 심각도 (CRITICAL/HIGH/MEDIUM/LOW) | LOW |
| `--parallel` | 병렬 처리 활성화 | OFF |
| `--ci` | CI 모드 (비대화형) | OFF |
| `--unmask` | credential 마스킹 해제 | 마스킹 ON |
| `--group` | 같은 credential 그룹핑 | OFF |
| `--cache` | mtime 기반 캐시 (변경 파일만 스캔) | OFF |
| `--incremental` | Git 변경 파일만 스캔 | OFF |
| `--no-entropy` | 엔트로피 분석 비활성화 | ON |
| `--baseline` | baseline 파일 경로 | .credscan-baseline.json |
| `--update-baseline` | 인터랙티브 baseline 업데이트 | - |
| `--install-hook` | Pre-commit 훅 설치 | - |
| `--config` | 설정 파일 경로 | config.yaml |
| `--rules` | 규칙 파일 경로 | rules.yaml |
| `--verbose`, `-v` | 상세 로그 출력 | OFF |

## 설정 커스터마이징

`config.yaml` 옆에 `config.local.yaml`을 만들면 자동으로 병합됩니다:

```yaml
# config.local.yaml (개인 환경 전용, .gitignore에 추가)
exclude_dirs:
  - .oh-my-zsh
  - my-large-folder
exclude_patterns:
  - ".*내_특정_파일.*"
```

- 리스트 값은 기존에 **합쳐지고**, 단일 값은 **덮어씁니다**
- `config.yaml`은 수정하지 마세요 — 업데이트 시 초기화됩니다

## 탐지 규칙 (29개)

| 카테고리 | 규칙 | 심각도 |
|---------|------|--------|
| AWS | Access Key (AKIA), Secret Key, Session Token | CRITICAL |
| Private Key | RSA, DSA, EC, OPENSSH, PGP | CRITICAL |
| HashiCorp | Vault Token (hvs.) | CRITICAL |
| GitHub | Personal/OAuth/Server Token (ghp_, gho_, ghs_) | HIGH |
| Slack | Token (xoxb/xoxp), Webhook | HIGH |
| Azure | Storage Connection String | HIGH |
| Stripe | Secret/Publishable/Restricted Key | HIGH |
| Twilio | API Key, Account SID | HIGH |
| SendGrid | API Key (SG.) | HIGH |
| GitLab | Personal Access Token (glpat-) | HIGH |
| Shopify | API Token (shpat_, shpss_) | HIGH |
| Password | 하드코딩된 패스워드, URL 내 패스워드 | HIGH |
| Google | API Key (AIza) | MEDIUM |
| JWT | JSON Web Token (eyJ) | MEDIUM |
| Database | MongoDB, PostgreSQL, MySQL URL | MEDIUM |
| Telegram | Bot Token | MEDIUM |
| Firebase | Database URL | MEDIUM |
| Generic | API Key, Encryption Key | MEDIUM/HIGH |
| Entropy | 고엔트로피 문자열 | LOW |

## 규정 준수

| 표준 | 준수율 |
|------|--------|
| OWASP Secrets Management | 95% |
| SARIF 2.1.0 (OASIS) | 100% |
| CWE-798 / CWE-321 | 100% |
| NIST SP 800-53 Rev 5 | 100% |
| PCI DSS v4.0 | 100% |

## 참고 기준

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [SARIF 2.1.0 (OASIS)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / [CWE-321](https://cwe.mitre.org/data/definitions/321.html)
- [Basak et al. (2023) — Secret Detection Tools 실증 연구](https://ar5iv.labs.arxiv.org/html/2307.00714)

## 테스트

```bash
python -m unittest test_scanner -v
# 33 tests, 0.5s
```

## 라이선스

MIT License — [LICENSE](LICENSE) 참조

## 면책조항

본 도구는 "있는 그대로(AS IS)" 제공됩니다. 상세 내용은 [DISCLAIMER.md](DISCLAIMER.md)를 참조하세요.

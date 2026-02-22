# 🐕 CredHound

로컬 파일에서 민감한 credential을 탐지하는 보안 도구.
OWASP, SARIF 2.1.0 등 업계 표준 준수.

## 주요 기능

- **30개 탐지 규칙** — AWS, GitHub, Slack, JWT, DB, 패스워드, Private Key 등
- **엔트로피 분석** — Shannon 엔트로피 기반 미지의 시크릿 탐지
- **다중 출력** — HTML 리포트, JSON, SARIF 2.1.0, 콘솔
- **CI/CD 연동** — exit code, 비대화형 모드, pre-commit 훅
- **병렬 처리** — ThreadPoolExecutor 기반 고속 스캔
- **credential 마스킹** — 결과 파일에 실제 값 노출 방지 (기본 ON)
- **false positive 관리** — baseline 파일로 오탐 제외
- **설정 분리** — 글로벌(config.yaml) + 개인(config.local.yaml) 자동 병합

## 설치

```bash
# 로컬 설치
pip install -e .

# 이후 어디서든
credhound --path ~ --parallel --format html -o report.html
```

## 빠른 시작

```bash
# 인터랙티브 모드 (HTML 리포트 자동 생성)
python3 main_v2.py

# 경로 지정
python3 main_v2.py --path ~/project

# 병렬 + HIGH 이상만
python3 main_v2.py --path ~ --parallel --severity HIGH
```

## 출력 형식

```bash
# HTML 리포트 (시각적, 권장)
python3 main_v2.py --path ~ --format html -o report.html

# JSON (프로그래밍적 소비)
python3 main_v2.py --path ~ --format json -o results.json

# SARIF 2.1.0 (GitHub Code Scanning 연동)
python3 main_v2.py --path ~ --format sarif -o results.sarif

# 콘솔 (기본)
python3 main_v2.py --path ~
```

## CI/CD 파이프라인

```bash
# CI 모드 (비대화형, exit code 반환)
python3 main_v2.py --path . --ci --severity HIGH
# exit 0 = clean, exit 1 = findings, exit 2 = error

# SARIF + CI
python3 main_v2.py --path . --ci --format sarif -o results.sarif

# Pre-commit 훅 설치
python3 main_v2.py --install-hook --path .
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

## 설정 파일

### config.yaml (글로벌 — 모든 사용자 공통)
```yaml
scan:
  max_workers: 4
  max_file_size: 10485760  # 10MB
exclude_dirs:
  - node_modules
  - .git
  - __pycache__
  # ...
```

### config.local.yaml (개인 환경 — .gitignore에 추가)
```yaml
# 글로벌에 병합됨 (리스트는 합침, 값은 덮어쓰기)
exclude_dirs:
  - .oh-my-zsh
exclude_patterns:
  - ".*내_특정_파일.*"
```

## 탐지 규칙 (30개)

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

## 참고 기준

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [SARIF 2.1.0 (OASIS)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [Basak et al. (2023) — Secret Detection Tools 실증 연구](https://ar5iv.labs.arxiv.org/html/2307.00714)

## 테스트

```bash
python3 -m unittest test_scanner -v
# 27 tests, 0.26s
```

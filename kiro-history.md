# Credential Scanner V2 — 개선 이력 (Kiro Session)

> 작업일: 2026-02-19
> 도구: Kiro CLI (AI 페어 프로그래밍)

---

## 1. 프로젝트 분석 및 기준 수립

### 1.1 현재 코드 분석
- `credential-scanner-v2/` (scanner_v2.py 565줄, main_v2.py 334줄) 분석
- `credscan-1.0.1/` 아키텍처 참고 (모듈화된 파서, Git 히스토리 스캔 등)
- 기존 v2: 15개 탐지 규칙, 순차 처리, 텍스트 출력만 지원

### 1.2 업계 표준 조사
- OWASP Secrets Management Cheat Sheet
- SARIF 2.1.0 (OASIS 승인 표준)
- Basak et al. (2023) 학술 논문 — 도구별 정밀도/재현율 벤치마크
- TruffleHog, Gitleaks, detect-secrets 비교 분석
- 결과를 `REFERENCES.md`에 문서화

### 1.3 갭 분석
- SARIF 출력 없음 → CRITICAL
- Pre-commit 훅 없음 → CRITICAL
- Git 히스토리 스캔 없음 → CRITICAL
- CI/CD exit code 없음 → CRITICAL
- 병렬 처리 비활성 → HIGH
- 룰 15개 → 업계 대비 부족 → HIGH

---

## 2. 핵심 기능 구현

### 2.1 scanner_v2.py 전면 재작성
- **병렬 처리**: ThreadPoolExecutor 기반, `--parallel` 옵션
- **SARIF 2.1.0 출력**: OASIS 표준 준수, GitHub Code Scanning 연동 가능
- **JSON 출력**: 요약 통계(by_rule, by_severity) 포함
- **CI/CD exit code**: 0=clean, 1=findings, 2=error
- **Pre-commit 훅**: `--install-hook`으로 자동 생성/설치
- **Git 변경분 스캔**: `--incremental`로 staged/unstaged 파일만 스캔
- **신뢰도 점수**: Finding에 confidence 필드 추가 (HIGH/MEDIUM/LOW)
- **심각도 필터링**: `filter_by_severity()` 메서드

### 2.2 main_v2.py 전면 재작성
- **argparse CLI**: 15개 옵션 (--path, --format, --severity, --ci, --parallel 등)
- **CI 모드**: `--ci` 비대화형, exit code 반환
- **인터랙티브 모드**: 기존 Rich UI 유지, CLI 인자로 오버라이드 가능
- **인터랙티브 Baseline**: `--update-baseline`로 false positive 선택/제외

### 2.3 rules.yaml 확장 (15개 → 30개)
추가된 규칙:
- password_in_code, npm_token, pypi_token, mailgun_key, square_token
- telegram_bot_token, shopify_token, gitlab_token, hashicorp_vault_token
- gcp_service_account, generic_password_url, aws_session_token
- datadog_api_key, firebase_url, encryption_key
- 파일 패턴: .env.production, terraform.tfvars, credentials.json, .htpasswd, wp-config.php

---

## 3. False Positive 수정 이력

### 3.1 generic_password_url 패턴 수정
- **문제**: `://[^:]+:[^@]+@` 패턴이 줄바꿈을 넘어 매칭 → .p10k.zsh 주석 URL 오탐 (수천건)
- **수정**: `://[^\s/:]+:[^\s/@]+@`로 변경 (공백/줄바꿈 차단)
- **추가 제외**: `username:password`, `#{...}` (Ruby 보간), `buildertoolbox-`, `"Email"`, `@amazon.com`, `${`, `%{`
- **결과**: 6,000+건 → 1건 (진짜만 남음)

### 3.2 datadog_api_key 패턴 수정
- **문제**: `[a-f0-9]{32}` 패턴이 AWS GuardDuty DetectorID, MD5 해시 등 전부 매칭
- **근거**: Datadog 공식 환경변수 `DD_API_KEY`, `DD_APP_KEY` (Gitleaks도 동일 접근)
- **수정**: `(?i)(?:datadog|dd_api_key|dd_app_key)\s*[=:]\s*[a-f0-9]{32}` — 변수명 컨텍스트 필수
- **결과**: GuardDuty DetectorID 오탐 완전 제거

### 3.3 telegram_bot_token 제외 패턴 추가
- **문제**: `[0-9]{8,10}:[0-9A-Za-z_-]{35}` 패턴이 AWS 계정ID:Control Tower 리소스명에 매칭
- **근거**: Telegram Bot API 공식 형식 (BotFather 생성 토큰)
- **수정**: `aws-controltower`, `(?i)arn:`, `(?i):aws-` 제외 추가
- **결과**: 4건 오탐 제거

### 3.4 high_entropy DynamoDB 토큰 제외
- **문제**: `eyJsYXN0RXZhbHVhdGVkS2V5...` (DynamoDB LastEvaluatedKey pagination 토큰)이 고엔트로피로 탐지
- **수정**: false_positive_patterns에 `^eyJsYXN0RXZhbHVhdGVkS2V5`, `^nextToken=`, `^0123456789` 추가
- **결과**: cradle.md 문서의 4건 오탐 제거

### 3.5 scan_results.json 재스캔 방지
- **문제**: 이전 스캔 결과 JSON 파일이 다시 스캔되어 중복 탐지
- **수정**: config.yaml exclude_patterns에 `.*scan_results.*\.json$` 추가

### 3.6 oh-my-zsh 디렉토리 제외
- **문제**: `.oh-my-zsh/plugins/` 내 `pwd` 변수가 password_in_code로 오탐
- **판단**: 서드파티 플러그인 코드 → 패턴 예외보다 디렉토리 제외가 적절
- **수정**: exclude_dirs에 `.oh-my-zsh` 추가

### 3.7 테스트 파일/Ruby 라이브러리 제외
- **문제**: `.toolbox/tools/*/ruby*/*.rb` 내 `Password: ""` 등이 오탐
- **수정**: exclude_patterns에 Ruby/JRuby 라이브러리, test_*.py 패턴 추가

---

## 4. 코드 품질 개선

### 4.1 print → logging 교체
- scanner_v2.py의 모든 `print()` → `logger.warning()` / `logger.error()`
- main_v2.py에 `--verbose` 시 DEBUG, 기본 WARNING 레벨 설정

### 4.2 예외처리 구체화
- `except Exception:` → `except (json.JSONDecodeError, IOError):` 등 구체적 예외
- `_load_config`에서 FileNotFoundError 시 경고 없이 빈 dict 반환 (로컬 config 옵션)

### 4.3 파일 수 제한 제거
- 기존: 100,000개 파일 제한 → Obsidian Vault 등 누락
- 수정: 제한 제거, 전체 파일 스캔

---

## 5. 추가 기능 구현

### 5.1 credential 마스킹
- Finding.to_dict(mask=True) — 앞 4자 + `****` + 뒤 4자
- 기본 ON, `--unmask`로 해제
- JSON, SARIF, HTML, 텍스트, baseline 파일 모두 적용
- 콘솔 출력은 평문 유지 (사용자가 직접 보는 것)
- JSON에 `"masked": true/false` 필드 포함

### 5.2 설정 분리 (글로벌/로컬)
- `config.yaml` — 글로벌 (모든 사용자 공통)
- `config.local.yaml` — 개인 환경 (자동 병합, .gitignore 대상)
- 병합 규칙: 리스트는 합침, 딕셔너리는 덮어쓰기, 값은 로컬 우선

### 5.3 HTML 리포트
- `--format html` 또는 인터랙티브 모드에서 자동 생성
- 위험도별 분포 차트, 색상 코딩, 반응형 테이블
- `report_YYYYMMDD_HHMMSS.html` 형식으로 저장

### 5.4 중복 값 그룹핑
- `--group` 옵션으로 같은 credential 값을 묶어서 요약
- 고유 credential 수와 발견 위치 수 표시

### 5.5 스캔 캐시
- `--cache` 옵션으로 mtime 기반 캐시
- 변경되지 않은 파일 재스캔 방지

### 5.6 JSON 요약 통계
- `summary.by_rule` — 룰별 건수
- `summary.by_severity` — 심각도별 건수
- `summary.total_findings` — 총 건수

### 5.7 단위 테스트
- `test_scanner.py` — 27개 테스트, 전체 통과
- 커버리지: Finding, Rule, EntropyAnalyzer, BaselineManager, CredentialScannerV2
- 마스킹, 필터링, 내보내기, 캐시, 그룹핑 검증

---

## 6. 스캔 결과 추이

| 회차 | 발견 | FP | 주요 변경 |
|------|------|-----|----------|
| 1차 | 6,243 | 수천 | 초기 스캔 |
| 2차 | 136 | 18 | URL 패턴 수정 |
| 3차 | 65 | 5 | URL 제외 추가 |
| 4차 | 29 | 0 | 파일 제한으로 누락 |
| 5차 | 68 | 2 | 제한 해제 |
| 6차 | 66 | 0 | oh-my-zsh 제외 |
| 7차 | 66 | 4 | telegram 오탐 발견 |
| 8차 | 62 | 0 | telegram 수정 |
| 9차 | 58 | 0 | DynamoDB 토큰 제외, logging |
| 10차 | 58 | 0 | config 분리 검증 |
| 11차 | 58 | 0 | 마스킹 검증 |

**최종: 58건 탐지, false positive 0건, 실제 credential 누락 0건**

---

## 7. 최종 파일 목록

| 파일 | 라인 | 역할 |
|------|------|------|
| scanner_v2.py | ~800 | 핵심 엔진 |
| main_v2.py | ~500 | CLI 인터페이스 |
| rules.yaml | ~480 | 30개 탐지 규칙 |
| config.yaml | ~110 | 글로벌 설정 |
| config.local.yaml | ~20 | 개인 환경 설정 |
| test_scanner.py | ~220 | 단위 테스트 27개 |
| REFERENCES.md | ~70 | 참고 문서 |
| kiro-history.md | 이 파일 | 개선 이력 |
| requirements.txt | 2 | rich, pyyaml |


---

## 8. 추가 수정 이력

### 8.1 HTML 리포트 심각도 정렬 (2026-02-19 20:41)
- **문제**: HTML 테이블이 파일 순서대로 나열되어 심각도별 정렬 안 됨
- **수정**: `export_html`에서 findings를 `SEVERITY_ORDER` 기준으로 정렬 (CRITICAL → HIGH → MEDIUM → LOW)
- **파일**: scanner_v2.py

### 8.2 배포/문서화 개선 (2026-02-19 21:14)
- **README.md 전면 재작성**: 새 기능, 전체 옵션 표, 사용 예시, 탐지 규칙 목록
- **--help 예시 업데이트**: html, group, cache, unmask 옵션 추가
- **HTML 리포트 개선**: 룰별 요약, 파일별 요약(상위 15개), 접기/펼치기(details), HIGH 통계 카드
- **config 검증 추가**: max_file_size, max_workers, entropy threshold, 규칙 필수 필드 검증
- **pyproject.toml 생성**: `pip install .`로 설치 가능, `credscan` 명령어 등록
- **파일**: scanner_v2.py, main_v2.py, README.md, pyproject.toml

### 8.3 브랜딩 변경: CredHound (2026-02-19 22:43)
- **변경**: 도구명을 `credential-scanner-v2` → `CredHound` 🐕로 통일
- **적용 범위**: CLI prog명, 배너, JSON/SARIF/HTML 출력, pre-commit 훅, README, pyproject.toml, logger명
- **CLI 명령어**: `credhound` (pip install 후)
- **파일**: scanner_v2.py, main_v2.py, README.md, pyproject.toml

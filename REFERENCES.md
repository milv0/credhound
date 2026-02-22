# Credential Scanner V2 - 참고 문서 및 업계 기준

## 업계 표준 (Industry Standards)

### OWASP Secrets Management Cheat Sheet
- URL: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- 시크릿 탐지 라이프사이클: 탐지(Detect) → 알림(Alert) → 교정(Remediate) → 로테이션(Rotate)
- 다중 탐지 방식 권장: 정규식 + 엔트로피 + 휴리스틱
- Pre-commit 예방 강조

### SARIF 2.1.0 (Static Analysis Results Interchange Format)
- URL: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif
- OASIS 승인 보안 도구 출력 표준
- GitHub Code Scanning, Azure DevOps 등과 연동 필수 포맷
- 스키마: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

### NIST Cybersecurity Framework
- URL: https://www.nist.gov/cyberframework
- 일반적 보안 가이드라인 제공 (시크릿 스캐닝 특화 기준은 없음)

### CIS Controls
- URL: https://www.cisecurity.org/controls
- 보안 모범 사례 제공 (시크릿 스캐닝 특화 벤치마크는 없음)

## 학술 연구 (Academic Research)

### Basak et al. (2023) - "An Empirical Study of Secret Detection Tools"
- URL: https://ar5iv.labs.arxiv.org/html/2307.00714
- 도구별 정밀도(Precision): GitHub Secret Scanner 75%, Gitleaks 46%, Commercial X 25%
- 도구별 재현율(Recall): Gitleaks 88%, SpectralOps 67%, TruffleHog 52%
- 8대 시크릿 카테고리: Private Keys, API Keys, Auth Tokens, Generic Secrets, DB URLs, Passwords, Usernames, Other
- False Positive 원인: 범용 정규식, 비효율적 엔트로피 계산
- False Negative 원인: 결함 있는 정규식, 파일 타입 누락, 불충분한 룰셋

## 업계 도구 비교 (Industry Tool Comparison)

### TruffleHog
- URL: https://github.com/trufflesecurity/trufflehog
- 800+ 탐지기, 엔트로피 + 정규식
- API 벤더 검증으로 false positive 대폭 감소
- Git 히스토리 스캔 지원

### Gitleaks
- URL: https://github.com/gitleaks/gitleaks
- TOML 설정 파일, 150+ 룰
- Git 히스토리 스캔, Pre-commit 훅
- SARIF 출력 지원
- 정밀도 46%, 재현율 88% (학술 벤치마크 기준)

### detect-secrets (Yelp)
- URL: https://github.com/Yelp/detect-secrets
- 베이스라인 파일 기반 시크릿 추적
- 플러그인 아키텍처
- 감사(Audit) 워크플로우

### git-secrets (AWS)
- URL: https://github.com/awslabs/git-secrets
- Pre-commit 훅 중심
- AWS 패턴 특화

## 도구 비교 참고
- URL: https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools

## 개선 기준 요약

| 카테고리 | 업계 기준 | V2 개선 목표 |
|---------|----------|------------|
| 탐지 정밀도 | >75% | 패턴 정교화 + 검증 |
| 탐지 재현율 | >80% | 룰셋 확장 (30+) |
| 출력 포맷 | SARIF 2.1.0 | SARIF + JSON 지원 |
| CI/CD 연동 | Exit code + 훅 | Non-zero exit + pre-commit |
| 성능 | <30s/100k LOC | 병렬 처리 활성화 |
| 시크릿 카테고리 | 8개 | 전체 커버 |
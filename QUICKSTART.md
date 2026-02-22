# 🚀 빠른 시작 가이드

## 1️⃣ 설치 (1분)

```bash
cd credential-scanner-v2
pip install -r requirements.txt
```

## 2️⃣ 첫 실행 - 테스트 (5초)

```bash
python test_scan.py
```

현재 디렉토리만 빠르게 스캔하여 동작을 확인합니다.

**예상 출력:**
```
테스트 스캔 시작: .
💡 Tip: 중단하려면 Ctrl+C를 누르세요

⠋ 파일 목록 생성 중...
⠙ 스캔 중... (15/20)
✓ 스캔 완료

✓ 스캔 완료!
파일명 패턴 매칭: 3개
내용 스캔 발견: 5개
스캔한 파일: 20개
발견한 파일: 20개
```

**💡 Tip: 언제든지 Ctrl+C를 눌러 스캔을 중단할 수 있습니다!**

## 3️⃣ 실제 스캔 (5-30분)

```bash
python main_v2.py
```

**프롬프트:**
```
스캔할 경로를 입력하세요 [/Users/username]: 
```

### 권장 스캔 경로

#### ✅ 추천: 특정 프로젝트
```
/Users/username/projects/my-app
```
- 빠름 (1-5분)
- 정확함
- 관리 용이

#### ⚠️ 주의: 홈 디렉토리
```
/Users/username
```
- 느림 (5-30분)
- 많은 결과
- 첫 실행 비추천

#### 🎯 최적: Obsidian Vault
```
/Users/username/Documents/ObsidianVault
```
- 중간 속도 (2-10분)
- credential 발견 확률 높음
- .env 파일 포함

## 4️⃣ 결과 확인

스캔 완료 후 터미널에 예쁜 UI로 표시됩니다:

```
╔══════════════════════════════════════════════════════════╗
║           🔐 CREDENTIAL SCANNER V2 RESULTS              ║
╚══════════════════════════════════════════════════════════╝

📊 위험도별 통계
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 CRITICAL  ████████████████████ 14
🟠 HIGH      ██████ 3
🟡 MEDIUM    ████ 2
🟢 LOW       ████████████████████████████████ 16
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 5️⃣ 결과 파일

스캔 결과는 자동으로 저장됩니다:

```
credential_scan_results_v2_YYYYMMDD_HHMMSS.txt
```

## 🎛️ 커스터마이징

### 더 빠르게 스캔하기

`config.yaml` 수정:
```yaml
scan:
  max_workers: 8  # CPU 코어 수만큼 증가

exclude_dirs:
  - Downloads  # 큰 디렉토리 제외
  - Movies
  - Music
```

### 더 정확하게 탐지하기

`config.yaml` 수정:
```yaml
entropy:
  threshold: 4.0  # 낮출수록 더 많이 탐지 (false positive 증가)
  min_length: 15  # 짧은 문자열도 탐지
```

### 새로운 규칙 추가하기

`rules.yaml`에 추가:
```yaml
rules:
  - id: my_custom_key
    name: 우리 회사 API 키
    severity: CRITICAL
    description: 회사 내부 API 키 패턴
    variable_patterns:
      - "company_api_key"
      - "internal_key"
    value_patterns:
      - pattern: "COMP_[A-Z0-9]{32}"
        name: "Company API Key Pattern"
```

## 🐛 문제 해결

### 스캔을 중단하고 싶을 때
```
Ctrl+C를 누르세요!
```
- 즉시 안전하게 종료됩니다
- 지금까지 스캔한 파일 수가 표시됩니다
- 부분 결과는 저장되지 않습니다

### 스캔이 너무 느림
```bash
# 1. 작은 디렉토리로 테스트
python test_scan.py

# 2. 제외 디렉토리 추가 (config.yaml)
exclude_dirs:
  - node_modules
  - .git
  - Downloads
```

### 스캔이 멈춤
- 정상입니다! 파일이 많으면 시간이 걸립니다
- 진행률 표시를 확인하세요: `스캔 중... (1234/5678)`
- 각 파일은 30초 타임아웃이 적용됩니다

### False Positive가 많음
```python
# baseline에 추가
from scanner_v2 import BaselineManager

baseline = BaselineManager('.credscan-baseline.json')
baseline.add_pattern_exclusion(r'TEST_.*', reason="테스트 키")
baseline.save_baseline()
```

## 📚 더 알아보기

- [README.md](README.md) - 전체 기능 설명
- [CHANGES.md](CHANGES.md) - 버그 수정 내역
- [config.yaml](config.yaml) - 설정 파일
- [rules.yaml](rules.yaml) - 탐지 규칙

## 💡 팁

1. **첫 실행**: 항상 `test_scan.py`로 테스트
2. **프로젝트별 스캔**: 홈 디렉토리보다 프로젝트 단위로
3. **정기 스캔**: 주 1회 프로젝트 디렉토리 스캔 권장
4. **Baseline 관리**: false positive는 baseline에 추가
5. **팀 공유**: `.credscan-baseline.json`을 Git에 커밋

## 🎯 다음 단계

1. ✅ `test_scan.py` 실행
2. ✅ 프로젝트 디렉토리 스캔
3. ✅ 결과 확인 및 false positive 제거
4. ✅ baseline 파일 생성
5. ✅ 정기 스캔 루틴 만들기

Happy Scanning! 🔐

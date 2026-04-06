# lswiz — Linux System Wizard

CentOS 7 EOL 보안 취약점 진단 및 리스크 스코어링 CLI 도구

## 프로젝트 목적

CentOS 7은 2024년 6월 30일부로 EOL에 도달하여 공식 보안 패치가 중단되었다. 본 도구는 EOL 환경에서 패치 없이 운영되는 서버의 보안 취약점을 탐지하고, 실행 가능한 완화 전략을 제시한다.

## 주요 기능

### 1. 환경 점검 (Preflight)
- 인터넷 연결 확인
- YUM 저장소 vault.centos.org 자동 전환
- 의존성 패키지 확인

### 2. 패키지 수집 (Scan)
- **RPM 패키지**: `rpm -qa`로 전체 수집
- **수동 설치 바이너리**: PATH 스캔 → RPM 미소속 바이너리 탐지
  - 바이너리별 전용 파서로 정확한 버전 추출
  - fallback: `--version` 범용 탐지

### 3. 바이너리 상태 분류
| 상태 | 설명 | 판별 방법 |
|------|------|----------|
| RUNNING | 프로세스 실행 중 | `ps`, `systemctl`, `ss` |
| INACTIVE | 사용 중이나 미실행 | systemd 등록, crontab, `/etc/` 참조 |
| UNUSED | 사용 흔적 없음 | 위 전부 해당 없음 |

### 4. CVE 매칭
- RPM → Red Hat Security API
- 수동 설치 → NVD API 2.0 (CPE 매칭)
- EOL 이후(2024-06-30~) CVE 필터링

### 5. 리스크 스코어링
```
contextual_score = CVSS × 상태가중치 × 네트워크가중치
```
- 서버 전체 등급: Critical / High / Medium / Low

### 6. 완화 전략 추천 (Doctor)
- RUNNING + 네트워크 노출 → 방화벽 차단 / 설정 강화
- INACTIVE → 서비스 해제 권고
- UNUSED + CVE → 삭제 권장
- UNUSED + CVE 없음 → 참고 목록 표시
- 전체 리스크 기반 마이그레이션 긴급도 판정

### 7. 결과 리포트
- 출력 형식: JSON, Text, HTML

## 기술 스택

| 항목 | 기술 |
|------|------|
| 언어 | Python 3.6, Bash |
| CVE 데이터 | Red Hat Security API, NVD API 2.0 |
| CLI | argparse |
| 설정 | YAML |
| 테스트 | pytest |

## 설치

### CentOS 7 (대상 OS)

```bash
# 1. Python 3 설치
sudo yum install -y python3 python3-pip

# 2. EOL로 인해 yum이 안 될 경우, vault 저장소로 전환 후 재시도
sudo sed -i 's/mirrorlist=/#mirrorlist=/g' /etc/yum.repos.d/CentOS-*.repo
sudo sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo
sudo yum install -y python3 python3-pip

# 3. lswiz 설치 (GitHub에서 직접)
pip3 install git+https://github.com/uzih05/lswiz.git

# 또는 소스에서 직접 설치
git clone https://github.com/uzih05/lswiz.git
cd lswiz
pip3 install -e .
```

### 설정 (선택)

```bash
# 기본 설정으로도 동작하지만, 커스텀 설정이 필요하면:
sudo mkdir -p /etc/lswiz
sudo cp config/config.yaml.example /etc/lswiz/config.yaml
# NVD API 키가 있으면 config.yaml에 추가 (속도 향상)
```

## 사용법

```bash
# root 권한으로 실행 권장 (시스템 전체 스캔)
sudo lswiz scan          # 패키지 수집 + CVE 매칭
sudo lswiz score         # scan + 리스크 스코어링
sudo lswiz doctor        # scan + score + 완화 전략 추천
sudo lswiz report        # 전체 파이프라인 + 리포트 출력
sudo lswiz full          # 전체 파이프라인 실행

# 리포트 형식 지정
sudo lswiz report --format json     # JSON 출력
sudo lswiz report --format html     # HTML 파일 생성
sudo lswiz report --format text     # 터미널 출력 (기본값)

# 커스텀 설정 파일 지정
sudo lswiz full -c /path/to/config.yaml
```

### 출력 예시

```
============================================================
  lswiz - Security Scan Report
============================================================

  Server Risk Grade: HIGH
  Max Risk Score:    8.2 / 10.0
  Total CVEs:        12
  Breakdown:         3 critical | 5 high | 4 medium

--- Vulnerable Packages ---

  nginx 1.12.2 [rpm] [RUNNING] score=8.2
    CVE-2024-XXXX CVSS=7.5 CTX=8.2 ...

--- Recommendations ---

  nginx:
    [HIGH] Restrict external access to port 80/tcp (nginx)
      firewall-cmd --permanent --remove-port=80/tcp
      firewall-cmd --reload

--- Migration Urgency ---
  Level: URGENT
  Multiple high-severity vulnerabilities. Plan migration within 30 days.
```

## 프로젝트 구조

```
lswiz/
├── lswiz/
│   ├── cli.py
│   ├── core/
│   │   ├── config.py
│   │   ├── logger.py
│   │   └── privilege.py
│   ├── preflight/
│   │   ├── network.py
│   │   └── repo.py
│   ├── scanner/
│   │   ├── rpm.py
│   │   ├── manual.py
│   │   ├── status.py
│   │   ├── registry.py
│   │   └── parsers/
│   │       ├── base.py
│   │       ├── generic.py
│   │       ├── nginx.py
│   │       ├── openssl.py
│   │       └── ...
│   ├── cve/
│   │   ├── redhat.py
│   │   └── nvd.py
│   ├── scoring/
│   │   └── risk.py
│   ├── doctor/
│   │   ├── firewall.py
│   │   ├── service.py
│   │   └── migrate.py
│   └── report/
│       ├── json_report.py
│       ├── text_report.py
│       └── html_report.py
├── tests/
├── config/
│   └── config.yaml.example
├── CLAUDE.md
└── README.md
```

## 라이선스

MIT

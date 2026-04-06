# lswiz — Linux System Wizard

## Project Overview
CentOS 7 EOL 보안 취약점 진단 및 리스크 스코어링 CLI 도구.

## Tech Stack
- Python 3.6 (CentOS 7 네이티브 호환)
- Bash (시스템 스크립트)
- Red Hat Security API + NVD API 2.0

## Rules
- Python 3.6 문법만 사용 (walrus operator :=, f-string = 디버깅 불가)
- 코드 변경 시 README.md 최신화 필수
- 타입 힌트는 `typing` 모듈 사용 (PEP 526 변수 어노테이션 가능, PEP 604 `X | Y` 불가)
- Co-Authored-By 커밋에 넣지 않음

## Architecture
```
lswiz/
├── cli.py              # CLI entry point (argparse)
├── core/               # 설정, 로깅, 권한
├── preflight/          # 환경 점검/복구
├── scanner/
│   ├── rpm.py          # RPM 패키지 수집
│   ├── manual.py       # 수동 설치 바이너리 탐지
│   ├── status.py       # RUNNING/INACTIVE/UNUSED 판별
│   ├── registry.py     # 파서 자동 등록/검색
│   └── parsers/        # 바이너리별 전용 파서
├── cve/
│   ├── redhat.py       # Red Hat Security API
│   └── nvd.py          # NVD API 2.0 (CPE 매칭)
├── scoring/            # 컨텍스트 기반 리스크 스코어링
├── doctor/             # 완화 전략 추천
└── report/             # JSON/Text/HTML 리포트
```

## Pipeline
Preflight → Scan → CVE Match → Risk Score → Doctor → Report

## Binary Status Classification
- RUNNING: 프로세스 실행 중 (ps, systemctl, ss)
- INACTIVE: 실행 중 아니지만 사용 흔적 있음 (systemd, crontab, /etc/ 참조)
- UNUSED: 사용 흔적 없음
  - CVE 있으면 → Doctor에서 "삭제 권장"
  - CVE 없으면 → 터미널에 참고 목록만 표시

## Parser Module
- 바이너리별 전용 파서 (parsers/*.py) → 정확한 버전 + CPE
- generic.py fallback → --version 시도
- 결과: CONFIRMED / DETECTED / UNKNOWN

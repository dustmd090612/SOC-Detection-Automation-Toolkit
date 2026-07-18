# 🛠️ SOC Detection & Automation Toolkit

보안관제(SOC) 및 탐지 엔지니어링(Detection Engineering) 실무 환경에서 발생하는 단순 반복 작업을 줄이고, 최신 고도화 위협에 실시간으로 대응하기 위해 제작한 보안 자동화 및 멀티 시그니처(Snort / YARA) 저장소입니다.

---

## 📂 저장소 구조 (Repository Structure)

```text
├── automation/                      # 파이썬 기반 업무 자동화 툴
│   ├── VirusTotal automation.py     # VT API 기반 IP 대량 분류 스크립트
│   └── requirements.txt             # 의존성 라이브러리 목록
│
└── detection-rules/                 # 위협 탐지 시그니처 통합 관리
    ├── snort/                       # 네트워크 침입 탐지 시스템 (NIDS) 룰
    │   └── critical_threats.rules   # 최신 취약점 및 Anubis C2 등 랜섬웨어 차단 시그니처
    └── yara/                        # 엔드포인트 및 파일 정적 분석 룰
        └── polinrider_campaign.yar  # 북한 APT 조직 유포 악성 패키지 탐지 시그니처
        └── labuba_rat.yar           # 엔비디아 위장 신종 라부바RAT 탐지 룰


1. 업무 자동화 도구 (Python Automation)
📍 VirusTotal API 기반 악성 IP 자동 분류 툴 (/automation)
방화벽(NGFW) 등 보안 장비에서 추출한 대량의 의심 IP 목록을 입력하면, VirusTotal v3 API를 호출하여 MALICIOUS / CLEAN / UNKNOWN 등급으로 자동 분류해 주는 파이썬 스크립트입니다.

핵심 기능:
무료 API 플랜 제한 회피 (16초 인터벌 타이머 내장)
2단계 IP 주소 유효성 검증 로직 반영
지수 백오프(Exponential Backoff) 에러 복구 알고리즘 적용

시작하기 (Quick Start)
필요한 라이브러리 설치:Bashpip install -r automation/requirements.txt
automation 폴더 안에 ips.txt 파일을 만들고 조회할 IP를 한 줄씩 입력한 뒤
실행:Bashexport VT_API_KEY="본인의_VirusTotal_API_키"
python automation/"VirusTotal automation.py"

🛡️ 2. 탐지 엔지니어링 (Detection Engineering)
최신 위협 인텔리전스(CTI) 리포트 및 침해사고 분석 데이터를 기반으로, 네트워크(Snort)와 엔드포인트(YARA) 영역을 아우르는 커스텀 시그니처를 개발합니다.

📍 침입 탐지 시그니처 (/detection-rules/snort)기업 환경의 외부 접점 인프라 취약점 및 최신 랜섬웨어의 지속 메커니즘을 탐지합니다. 한글 윈도우 인코딩 환경에서 발생할 수 있는 정규표현식(pcre) 문법 오류를 전면 최적화했습니다.
📍 호스트 기반 정적 분석 시그니처 (/detection-rules/yara)개발자 생태계 및 공급망 공격을 수행하는 APT 그룹의 고유한 파일 아티팩트 및 인코딩 패턴을 식별하여 악성 바이너리를 정적으로 탐지합니다.


🎯 주요 탐지 커버리지 (Coverage)

Snort
최신 취약점 및 랜섬웨어	CitrixBleed 2 Auth Bypass (CVE-2025-5777), Palo Alto PAN-OS Auth Bypass (CVE-2026-0300), Oracle OIM RCE (CVE-2026-21992), Langflow Unauthenticated RCE (CVE-2026-33017)
인텔리전스 기반 C2 차단	Anubis (Sphinx) 랜섬웨어 공격 인프라 (Remotely C2, MeshAgent C2, Typosquatted ScreenConnect Relay, MEGA S4 Exfiltration Path), 신종 라부바RAT (LabubaRAT) C2 패널 통신 탐지
인프라 및 시스템 RCE	Apache log4j RCE, Microsoft HTTP.sys RCE (CVE-2021-31166), SMBGhost (CVE-2020-0796), Redis RCE (CVE-2022-0543)
엔터프라이즈 솔루션	Cisco ISE (CVE-2026-20029), Confluence OGNL Injection (CVE-2023-22527), Citrix NetScaler RCE (CVE-2023-3519), ipTIME CGI Session Bypass (CVE-2026-24498)

YARA
APT / 공급망 공격     	**북한 해커 조직 (Contagious Interview)**의 개발자 타깃 오픈소스 공급망 공격 (PolinRider 캠페인 악성 패키지 SHA-256 탐지)
신종 원격 제어(RAT)      **엔비디아(NVIDIA) 컨테이너 툴킷 위장 Rust 기반 원격 제어 악성코드  (LabubaRAT 호스트 프로파일링 및 내부 SQLite 로직 정적 탐지) 

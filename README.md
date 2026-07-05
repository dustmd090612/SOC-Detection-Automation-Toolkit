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
    │   └── critical_threats.rules   # 최신 취약점 및 Anubis C2 차단 시그니처
    └── yara/                        # 엔드포인트 및 파일 정적 분석 룰
        └── polinrider_campaign.yar  # 북한 APT 조직 유포 악성 패키지 탐지 시그니처


1. 업무 자동화 도구 (Python Automation)
📍 VirusTotal API 기반 악성 IP 자동 분류 툴 (/automation)방화벽(NGFW) 등
보안 장비에서 추출한 대량의 의심 IP 목록을 입력하면, VirusTotal v3 API를 호출하여 MALICIOUS / CLEAN / UNKNOWN 등급으로자동 분류해 주는 파이썬 스크립트입니다.
핵심 기능:무료 API 플랜 제한 회피 (16초 인터벌 타이머 내장)2단계 IP 주소 유효성 검증 로직 반영지수 백오프(Exponential Backoff) 에러 복구 알고리즘 적용

🚀 시작하기 (Quick Start)필요한 라이브러리 설치:Bashpip install -r automation/requirements.txt
automation 폴더 안에 ips.txt 파일을 만들고 조회할 IP를 한 줄씩 입력한 뒤
실행:Bashexport VT_API_KEY="본인의_VirusTotal_API_키"
python automation/"VirusTotal automation.py"

🛡️ 2. 탐지 엔지니어링 (Detection Engineering)
📍 커스텀 네트워크 위협 탐지 시그니처 (/detection-rules/snort)기업 환경에서 가장 치명적인 주요 인프라 취약점 및 최신 CVE 공격을 탐지하기 위해 직접 정제하고 검증한 커스텀 Snort 시그니처 집합입니다.
실무 환경에 맞춰 한 파일(critical_threats.rules)로 통합 관리하고 있습니다.

🎯 주요 탐지 커버리지 (Coverage)분류탐지 대상 및 주요 CVE최신 위협 (2026 CVE)Palo Alto PAN-OS Auth Bypass (CVE-2026-0300), Oracle OIM RCE (CVE-2026-21992), Langflow Unauthenticated RCE (CVE-2026-33017),
Open Redirect (CVE-2026-22029)인프라 및 시스템 RCEApache log4j RCE, Microsoft HTTP.sys RCE (CVE-2021-31166), SMBGhost (CVE-2020-0796), Redis RCE (CVE-2022-0543)엔터프라이즈 솔루션Cisco ISE (CVE-2026-20029),
Confluence OGNL Injection (CVE-2023-22527), Citrix NetScaler RCE (CVE-2023-3519)개발자 생태계 & 공급망Node.js TLS SNI DoS (CVE-2026-21637), LiteLLM SQLi (CVE-2026-42208),
Axios Supply Chain 타깃 공격IoT & 기타 통신 인프라Dahua Loopback Auth Bypass (CVE-2021-33044/45), free5GC UDR Fail-Open (CVE-2026-40343), ipTIME CGI Session Bypass (CVE-2026-24498)

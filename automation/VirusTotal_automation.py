import truststore
truststore.inject_into_ssl()

import os
import re
import time
import requests
from tqdm import tqdm

VT_BASE = "https://www.virustotal.com/api/v3"
IP_ENDPOINT = VT_BASE + "/ip_addresses/{ip}"
MIN_INTERVAL_SEC = 16.0
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def is_valid_ipv4(ip: str) -> bool:
    """1단계 형식(Regex) 및 2단계 범위(0~255)를 포함한 종합 IP 유효성 검사"""
    if not IP_RE.match(ip):
        return False
    parts = ip.split(".")
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def read_ips_txt(path: str) -> list[str]:
    """텍스트 파일로부터 IP 리스트를 읽어와 주석 처리 및 중복을 제거하는 정제 함수"""
    ips = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            ips.append(s)
    
    # 순서를 유지한 채 중복 제거(Deduplication)
    seen = set()
    uniq = []
    for ip in ips:
        if ip not in seen:
            uniq.append(ip)
            seen.add(ip)
    return uniq

def vt_lookup(api_key: str, ip: str):
    """VirusTotal API v3 엔드포인트 세션 연결 및 쿼리 요청 수행"""
    headers = {"x-apikey": api_key, "accept": "application/json"}
    url = IP_ENDPOINT.format(ip=ip)
    r = requests.get(url, headers=headers, timeout=20)
    try:
        data = r.json()
    except Exception:
        data = {}
    return r.status_code, data

def extract_result(status: int, data: dict):
    """응답 JSON 페이로드 분석을 통한 최종 스코어 및 관제 등급 맵핑"""
    attrs = (((data or {}).get("data") or {}).get("attributes") or {})
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    
    if malicious >= 1:
        return "MALICIOUS", malicious
    if status == 200:
        return "CLEAN", malicious
    return "UNKNOWN", malicious

def main():
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("❌ 환경변수 VT_API_KEY가 존재하지 않습니다. 설정을 확인해 주세요.")
        return

    ips = read_ips_txt("ips.txt")
    last_call_time = 0.0

    with open("result.txt", "w", encoding="utf-8") as out:
        out.write("IP | RESULT | MALICIOUS\n")
        out.write("-" * 40 + "\n")
        
        # tqdm 프로그래스 바 연동으로 실시간 관제 진행도 시각화
        for ip in tqdm(ips, desc="VirusTotal 실시간 조회 중"):
            if not is_valid_ipv4(ip):
                out.write(f"{ip} | INVALID_IP | 0\n")
                continue
                
            # API 분당 속도 제어를 위한 인터벌 타이머 계산
            elapsed = time.time() - last_call_time
            if elapsed < MIN_INTERVAL_SEC:
                time.sleep(MIN_INTERVAL_SEC - elapsed)
                
            # 지수 백오프 기반 재시도 루프 실행
            for attempt in range(5):
                status, data = vt_lookup(api_key, ip)
                last_call_time = time.time()
                if status == 429:
                    time.sleep(20 + attempt * 20)
                    continue
                break
                
            result, mal = extract_result(status, data)
            out.write(f"{ip} | {result} | {mal}\n")

    print(f"\n✅ 분석 완료! 최종 결과 리포트 저장 위치: result.txt")

if __name__ == "__main__":
    main()

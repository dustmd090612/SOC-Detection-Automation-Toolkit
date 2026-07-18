rule Win_Malware_LabubaRAT_2026 {
    meta:
        description = "Detects LabubaRAT, a Rust-based RAT masquerading as NVIDIA software"
        author = "Yu Yeon-seung"
        date = "2026-07-18"
        reference = "Blackpoint Cyber Intelligence Report"
        severity = "Critical"
        os = "Windows"

    strings:
        // 1. Rust 바이너리 및 런타임 주입 특징 문자열
        $rust_1 = "rustc" ascii
        $rust_2 = "core::result::Result" ascii
        
        // 2. 호스트 프로파일링 및 보안 도구 식별 대상 문자열
        $sec_1 = "CrowdStrike" ascii nocase
        $sec_2 = "SentinelOne" ascii nocase
        $sec_3 = "WinDefend" ascii nocase
        $browser_1 = "Google\\Chrome" ascii nocase
        $browser_2 = "Microsoft\\Edge" ascii nocase

        // 3. 구성 정보 저장을 위한 로컬 SQLite 특징
        $sqlite = "SQLite format 3" ascii
        
        // 4. 위장 및 파일명 아티팩트
        $fake_nv = "nvidia-sysruntime.exe" ascii nocase

    condition:
        uint16(0) == 0x5A4D and // MZ Header
        (
            // 엔비디아 파일명을 사칭하면서 러스트 기반이고 보안 도구를 수집하는 행위 조합
            ($fake_nv and all of ($rust*)) or
            (all of ($rust*) and 2 of ($sec*) and 1 of ($browser*) and $sqlite)
        )
}

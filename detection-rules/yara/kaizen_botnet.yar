rule ELF_Malware_Kaizen_Botnet_ARM {
    meta:
        description = "Detects Kaizen botnet ELF binaries targeting ARM architecture"
        author = "Yu Yeon-seung"
        date = "2026-07-20"
        reference = "Kaizen Botnet OS Command Injection Incident Analysis"
        severity = "Critical"
        arch = "ARM"

    strings:
        // 1. ELF Header (Executable and Linkable Format)
        $elf = { 7F 45 4C 46 }
        
        // 2. Kaizen / Mirai 계열 봇넷 아티팩트 및 식별자
        $str_kaizen = "kaizen" ascii nocase
        $str_bot_1 = "PING" ascii
        $str_bot_2 = "PONG" ascii
        $str_ddos = "ATTACK" ascii nocase
        
        // 3. 공격자 서명 문자열
        $ua_sig = "r00ts3c" ascii

    condition:
        $elf at 0 and
        (
            $str_kaizen or$ua_sig or
            all of ($str_bot*) or
            ($str_ddos and 2 of ($str_*))
        )
}

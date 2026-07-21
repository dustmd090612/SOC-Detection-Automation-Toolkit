rule ELF_Malware_NadMesh_Go_Botnet {
    meta:
        description = "Detects NadMesh Go-based autonomous botnet targeting AI and MCP infrastructure"
        author = "Yu Yeon-seung"
        date = "2026-07-21"
        reference = "Qianxin X-Lab Threat Intelligence Report"
        severity = "Critical"
        os = "Linux"

    strings:
        // 1. Go 언어 바이너리 아티팩트
        $go_build = "Go build ID:" ascii
        $go_rt = "runtime.goexit" ascii

        // 2. AI 및 MCP 인프라 타깃 문자열
        $target_1 = "11434" ascii      // Ollama Port
        $target_2 = "8188" ascii       // ComfyUI Port
        $target_3 = "/mcp" ascii
        $target_4 = "/sse" ascii
        $shodan = "api.shodan.io" ascii nocase

        // 3. 지속성 및 자격 증명 탈취 아티팩트
        $persist_1 = "authorized_keys" ascii
        $persist_2 = "crontab" ascii
        $cred_1 = "AWS_ACCESS_KEY_ID" ascii
        $cred_2 = "AWS_SECRET_ACCESS_KEY" ascii

    condition:
        uint32(0) == 0x464C457F and // ELF Header
        all of ($go_*) and
        (
            $shodan or
            2 of ($target_*) or
            (any of ($persist_*) and any of ($cred_*))
        )
}

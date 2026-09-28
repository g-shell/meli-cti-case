/*
    CTI-2026-0927-001 — Dropper macOS (ecossistema AMOS / MacSync) via ClearFake
    Hash de referência: 7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e

    Fidelidade:
      - MELI_MacOS_Dropper_AppsBin_7a8fc48c ........ ALTA  (hash + identifier da assinatura ad-hoc)
      - MELI_MacOS_LaunchAgent_RandomLabel_Plist ... MÉDIA (padrão observado em sandbox; hunting em disco)
      - MELI_MacOS_Dropper_LaunchAgent_Hunting ..... BAIXA (hipótese; strings não validadas contra o binário)
      - MELI_Script_ClickFix_Loader_Hunting ........ BAIXA (hipótese; padrão de loaders ClearFake/AMOS)

    As regras de baixa fidelidade não foram validadas contra o binário original:
    o download da amostra não estava disponível na conta do MalwareBazaar/URLhaus
    usada na análise. Rode-as primeiro em modo hunting.
*/

import "hash"

rule MELI_MacOS_Dropper_AppsBin_7a8fc48c
{
    meta:
        author = "MELI CTI"
        date = "2026-09-27"
        description = "Mach-O universal (x86_64+arm64) assinado ad-hoc, distribuído como apps.bin via ClearFake"
        reference = "CTI-2026-0927-001"
        sha256 = "7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e"
        cdhash = "05500000f2400da6dc207cb3a1bd44e20b2e12ba"
        fidelity = "high"
        mitre_attack = "T1543.001, T1553.001"

    strings:
        // Identifier do CodeDirectory (assinatura ad-hoc, sem Team ID).
        $codesign_id = "9e410d7320e53cfa145597824b9f6060UBF-55554944d1782379f5233c60914e582ab6e79e25" ascii

    condition:
        // FAT_MAGIC / FAT_CIGAM
        (uint32be(0) == 0xCAFEBABE or uint32be(0) == 0xBEBAFECA)
        and filesize < 200KB
        and (
            $codesign_id
            or hash.sha256(0, filesize) == "7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e"
        )
}

rule MELI_MacOS_LaunchAgent_RandomLabel_Plist
{
    meta:
        author = "MELI CTI"
        date = "2026-09-27"
        description = "LaunchAgent com label com.<usuário>.<16 letras> apontando para ~/Library/<16 letras> (persistência observada em sandbox)"
        reference = "CTI-2026-0927-001"
        example = "com.root.gfskjsnghdjsvuxj.plist -> /private/var/root/Library/gfskjsnghdjsvuxj"
        fidelity = "medium"
        usage = "Varredura de ~/Library/LaunchAgents e /Library/LaunchAgents"
        mitre_attack = "T1543.001"

    strings:
        $plist = "<plist" ascii
        $label = /<key>Label<\/key>\s*<string>com\.[A-Za-z0-9_.-]{1,64}\.[a-z]{16}<\/string>/ ascii
        $program = /<string>[^<]{0,128}\/Library\/[a-z]{16}<\/string>/ ascii
        $run_at_load = "RunAtLoad" ascii

    condition:
        filesize < 8KB
        and $plist
        and $label
        and ($program or $run_at_load)
}

rule MELI_MacOS_Dropper_LaunchAgent_Hunting
{
    meta:
        author = "MELI CTI"
        date = "2026-09-27"
        description = "HIPÓTESE: Mach-O pequeno que oculta o Terminal e instala LaunchAgent via launchctl"
        reference = "CTI-2026-0927-001"
        fidelity = "low"
        validated_against_sample = "false"
        mitre_attack = "T1543.001, T1059.004, T1564"

    strings:
        $cmd_killall = "killall Terminal" ascii
        $cmd_launchctl = "launchctl load" ascii
        $path_agents = "Library/LaunchAgents" ascii
        $shell = "/bin/sh" ascii
        $plist_ext = ".plist" ascii
        $osascript = "osascript" ascii

    condition:
        (
            uint32be(0) == 0xCAFEBABE or uint32be(0) == 0xBEBAFECA
            or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE
        )
        and filesize < 2MB
        and $cmd_launchctl
        and $path_agents
        and 2 of ($cmd_killall, $shell, $plist_ext, $osascript)
}

rule MELI_Script_ClickFix_Loader_Hunting
{
    meta:
        author = "MELI CTI"
        date = "2026-09-27"
        description = "HIPÓTESE: shell loader pequeno (ClearFake/ClickFix, AMOS) que baixa, libera e executa binário"
        reference = "CTI-2026-0927-001"
        related_sha256 = "b34241006b130412756e834250f2f73da11f895183040618e030b50b5951da9a"
        fidelity = "low"
        validated_against_sample = "false"
        mitre_attack = "T1204.004, T1059.004, T1105, T1553.001"

    strings:
        $curl = /curl\s+[^\n]{0,64}-[a-zA-Z]*[oO]\s/ ascii
        $tmp = /\/(private\/)?tmp\// ascii
        $chmod = /chmod\s+(\+x|[0-7]{3,4})/ ascii
        $xattr = /xattr\s+-[a-z]*[cd]/ ascii

    condition:
        // Instaladores legítimos também usam curl + chmod: revisar hits.
        filesize < 4KB
        and $curl
        and $tmp
        and ($chmod or $xattr)
}

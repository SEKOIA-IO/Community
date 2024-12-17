rule sekoiaio_apt_unc4990_explorer_ps1_reverse_b64 {
    meta:
        id = "35c3ffb2-2ced-426c-ac3f-a8cd0c357672"
        version = "1.0"
        description = "Detects reverse base64 files (explorer.ps1)"
        author = "Sekoia.io"
        creation_date = "2024-02-01"
        classification = "TLP:CLEAR"
        
    strings:
        $s0 = "Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\""
        $s1 = "Wa1VHJ\"[-1..-"
        $s2 = "-join '')))"
        
    condition:
        all of them and $s0 at 0 and @s2 - @s2 < 20
}
        
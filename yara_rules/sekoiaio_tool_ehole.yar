rule sekoiaio_tool_ehole {
    meta:
        id = "7d30ffd0-fada-4ef4-98c3-5572a4e1e140"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-06-23"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "main.http400"
        $s2 = "main.fofa_c"
        $s3 = "main.Jsjump"
        $s4 = "main.StandBase64"
        $s5 = "main.fofa_http"
        $s6 = "main.fofa_seach"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 11MB and
        all of them
}
        
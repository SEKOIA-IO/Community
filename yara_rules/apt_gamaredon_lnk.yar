rule apt_gamaredon_lnk {
    meta:
        id = "bfa69d84-433c-4f37-93b7-5b1b11677fbb"
        version = "1.0"
        description = "Detects lnk file used by Gamaredon"
        author = "Sekoia.io"
        creation_date = "2024-02-08"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "-windowstyle hidden $(gc " wide
        $s2 = "|out-string)|powershell -noprofile -" wide
        
    condition:
        uint32be(0) == 0x4c000000 and any of them  and filesize < 100KB
}
        
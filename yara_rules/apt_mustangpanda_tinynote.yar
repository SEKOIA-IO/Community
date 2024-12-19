rule apt_mustangpanda_tinynote {
    meta:
        id = "a2b9bea4-a211-456f-8a3f-0f31733e8b29"
        version = "1.0"
        description = "Detects strings in TinyNote backdoor"
        author = "Sekoia.io"
        creation_date = "2023-06-07"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "bypassSMADAV" ascii fullword
        $s2 = "excuteCmdLine" ascii fullword
        $s3 = "/Create1953125" ascii
        $s4 = "MINUTEMonday" ascii
        $s5 = "WndProc" ascii
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 8MB and
        all of them
}
        
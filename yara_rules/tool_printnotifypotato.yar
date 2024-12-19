rule tool_printnotifypotato {
    meta:
        id = "8dde175f-025a-4c27-bcc6-d0016dd7238c"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-08-23"
        classification = "TLP:CLEAR"
        author = "Sekoia.io"
        
    strings:
        $s1 = "PrintNotifyPotato.exe" ascii wide
        $s2 = "BeichenDream" ascii wide
        $s3 = "interactive" ascii wide
        $s4 = "DuplicateTokenEx" ascii wide
        $s5 = "CurrentUser" ascii wide
        $s6 = "FakeIUnknown" ascii wide
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 8MB and
        all of them
}
        
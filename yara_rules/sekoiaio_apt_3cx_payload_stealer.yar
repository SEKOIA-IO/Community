rule sekoiaio_apt_3cx_payload_stealer {
    meta:
        id = "1ca0605d-101f-4d1d-a476-9dfd93e74b4c"
        version = "1.0"
        description = "Detects stealer used in 3CX campaign"
        author = "Sekoia.io"
        creation_date = "2023-03-31"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "******************************** %s ******************************" wide
        $s2 = "\\3CXDesktopApp\\config.json" wide
        $s3 = "{\"HostName\": \"%s\", \"DomainName\": \"%s\", \"OsVersion\":" wide
        $s4 = "%s.old" wide
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 8MB and
        all of them
}
        
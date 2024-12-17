rule sekoiaio_apt_mustangpanda_coolclient {
    meta:
        id = "2f8fdb66-03a2-400f-808b-56ae1b276d2f"
        version = "1.0"
        description = "Detect COOLCLIENT via obfuscation & specific string"
        author = "Sekoia.io"
        creation_date = "2023-03-27"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = {eb 14 ea 50 eb 0b ea 8b c4 a8 01 74 06 eb 0b}
        $s2 = {66 0f d6 44 24 eb eb}
        $s3 = "c:\\windows\\syste" fullword
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 1MB and
        all of them
}
        
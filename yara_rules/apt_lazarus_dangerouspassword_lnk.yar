rule apt_lazarus_dangerouspassword_lnk {
    meta:
        id = "32533880-7f75-4682-a7ae-9868d0b5174b"
        version = "1.0"
        description = "Detects Lazarus DangerousPassword LNKs"
        author = "Sekoia.io"
        creation_date = "2022-07-26"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = {6D 00 73 00 68 00 2A}
        $s2 = {25 00 70 00 75 00 62 00 6C 00 69 00 63 00 25}
        $s3 = {44 00 4F 00 20 00 73 00 74 00 61 00 72 00 74}
        $b1 = {2F 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2F 00 62 00 20 00 6D 00 73 00 68 00 74 00 61}
        $c1 = {68 00 74 00 74 00 70 00 73 00 3A 00 2F 00 2F 00 62 00 69 00 74 00 2E 00 6C 00 79 00 2F}
        
    condition:
        uint32be(0)== 0x4C000000 and
        filesize > 1KB and filesize < 40MB and
        (all of ($s*) or $b1 or ($s1 and $c1))
}
        
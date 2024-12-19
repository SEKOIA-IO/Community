rule apt_mustangpanda_malicious_lnk_worm {
    meta:
        id = "e7cc5ecc-2369-49ff-9e35-c9faeb69acda"
        version = "1.0"
        description = "Detects MustangPanda infected ThumbDrive"
        author = "Sekoia.io"
        creation_date = "2023-09-21"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "RECYCLER.BIN\\1\\CEFHelper.exe" wide
        
    condition:
        uint32be(0) == 0x4C000000 and
        1 of them
}
        
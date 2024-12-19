rule apt_rusticweb_stealer {
    meta:
        id = "813072e0-28de-4cb7-b2cc-71d77a1e8508"
        version = "1.0"
        description = "Detects stealer used by RusticWeb"
        author = "Sekoia.io"
        creation_date = "2024-01-09"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "-FTT=@"
        $s2 = "https://oshi.at"
        $s3 = "curl-T"
        $s4 = "upload/upload.php"
        $s5 = "cargo"
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 4MB and 3 of them
}
        
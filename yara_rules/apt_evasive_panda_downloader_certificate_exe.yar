rule apt_evasive_panda_downloader_certificate_exe {
    meta:
        id = "1b40fca9-04b1-46b3-b48c-5a148a1b36b9"
        version = "1.0"
        description = "Detects downloader used by Evasive Panda (certificate.exe)"
        author = "Sekoia.io"
        creation_date = "2024-03-15"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = {C6 45 D4 44 C6 45 D5 74 C6 45 D6 7C C6 45 D7 74 C6 45 D8 79}
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        
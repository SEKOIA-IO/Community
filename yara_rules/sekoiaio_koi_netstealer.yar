rule sekoiaio_koi_netstealer {
    meta:
        id = "deb06e2a-848c-44b3-be95-017ebccf11f8"
        version = "1.0"
        description = "Detects NET ofbuscated Stealer used loaded by KoiLoader"
        source = "Sekoia.io"
        creation_date = "2024-03-20"
        classification = "TLP:CLEAR"
        
    strings:
        $name_1 = "pg20"
        $name_2 = "pg40"
        $s1 = "Curve25519"
        $s2 = "ConsoleApp"
        $s3 = "e0d2eec7-eb14-48ba-8709-dcc9de65947d"
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 150KB and 
        any of ($name_*) and all of ($s*)
}
        
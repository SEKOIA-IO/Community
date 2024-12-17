rule sekoiaio_pe_stealer_axilestealer_strings {
    meta:
        id = "412bfc3e-6bb7-4b0d-8bb3-96eae0cc9782"
        version = "1.0"
        description = "AxileStealer strings"
        author = "Sekoia.io"
        creation_date = "2023-12-13"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "http://ip-api.com/line/?fields=query,country,countryCode,city,regionName,zip,isp" wide
        $s2 = "Axile.su" wide
        $s3 = "Unknown Tokens.txt" wide
        $a1 = "[ <b>General</b> ]" wide
        $a2 = "[ <b>Browsers</b> ]" wide
        $a3 = "[ <b>Wallets</b> ]" wide
        $a4 = "[ <b>Messengers</b> ]" wide
        $a5 = "[ <b>Applications</b> ]" wide
        $a6 = "[ <b>Games</b> ]" wide
        $a7 = "[ <b>Mails</b> ]" wide
        $a8 = "[ <b>VPNs</b> ]" wide
        $a9 = "[ <b>FTPs</b> ]" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize > 50KB and filesize < 200KB and
        2 of ($s*) and 7 of ($a*)
}
        
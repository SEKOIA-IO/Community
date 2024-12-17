rule sekoiaio_win_infostealer_serpent_strings {
    meta:
        id = "ad9e2366-c95e-4090-a0db-48f3cc325209"
        version = "1.0"
        description = "Serpent Stealer string"
        author = "Sekoia.io"
        creation_date = "2023-12-04"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "User Has SSH Dir." wide
        $s2 = "[+] Executing Wallets" wide
        $s3 = "'serpent' folder" wide
        $s4 = "Buddy Kys!!!" wide
        $s5 = "http://checkip.dyndns.org/" wide
        $s6 = "[+] Target has discord installed" wide
        $s7 = "Target has minecraft." wide
        
    condition:
        (uint16be(0) == 0x4d5a) and
        filesize < 100KB and
        5 of them
}
        
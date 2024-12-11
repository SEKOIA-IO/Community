rule sekoiaio_ransomware_win_dodo_2023 {
    meta:
        id = "190977d4-5a7a-4e15-8f90-085f82ec56c8"
        version = "1.0"
        description = "Rule to detect Dodo ransomware samples."
        source = "Sekoia.io"
        creation_date = "2023-02-13"
        classification = "TLP:CLEAR"
        hash1 = "aee45cc2540d49a28e765c30f1c4d0b853c1a74ea2260bd7614ece8e54c3bcb3"
        
    strings:
        $s1 = "DODOCRYPTER" ascii wide
        $s2 = "dodov2" ascii wide
        $s3 = "dodov2SPREAD.exe" ascii wide
        $s4 = "dodov2_readit.txt" ascii wide
        $s5 = "WELCOME, DODO has returned" ascii wide
        $s6 = "Monero Address: 442n8nf9zojie1JdkZqxDQJFDumBEgZmVZozLdYd5jVPSMws2oUPvNLJKca6JKojyA7zDCZCnMyYnKbY1JLNsbzWK6HNNqW" ascii wide
        $s7 = "The price for the software is $15. Payment can be made in Bitcoin or XMR." ascii wide
        
    condition:
        uint16be(0) == 0x4d5a  and 4 of them
}
        
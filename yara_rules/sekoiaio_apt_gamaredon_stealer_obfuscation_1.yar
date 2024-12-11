rule sekoiaio_apt_gamaredon_stealer_obfuscation_1 {
    meta:
        id = "a6197d16-8ed1-410b-8814-d7eff9a8096c"
        version = "1.0"
        description = "Matches the Gamaredon Stealer obfuscation"
        source = "Sekoia.io"
        creation_date = "2022-02-04"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = { 76 61 72 20 [5-30] 3d 20 6e 65 77 20 6f 62 6a 65 63 74 5b 5d 20 7b 20 [2-10] 2c 20 [2-10] 2c 20 [2-10] 2c 20 [2-10] 2c 20 [2-10] 2c 20 [2-10] 20 7d 3b }
        $s2 = { 66 6f 72 28 69 6e 74 20 [5-30] 20 3d 20 30 3b 20 [5-30] 20 3c 20 31 30 3b 20 [5-30] 2b 2b 29 }
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize > 100MB and
        (#s1 > 100 or #s2 > 100)
}
        
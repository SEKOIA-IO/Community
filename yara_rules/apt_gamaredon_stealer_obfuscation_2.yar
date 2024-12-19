rule apt_gamaredon_stealer_obfuscation_2 {
    meta:
        id = "fd278a90-537b-4c67-9421-01c9f2416b60"
        version = "1.0"
        description = "Matches the Gamaredon Stealer obfuscation"
        author = "Sekoia.io"
        creation_date = "2022-02-04"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = { 3d 20 6e 65 77 20 73 74 72 69 6e 67 5b 5d 20 7b 20 [50-200] 20 7d 3b }
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize > 100MB   and
        #s1 > 40
}
        
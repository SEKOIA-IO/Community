rule sekoiaio_apt_sidecopy_cheex {
    meta:
        id = "e9b57f15-e703-4367-b501-fa8a873e4455"
        version = "1.0"
        description = "Detects PDB path of Cheex"
        author = "Sekoia.io"
        creation_date = "2024-08-14"
        classification = "TLP:CLEAR"
        hash = "825c7a1603f800ff247c8f3e9a1420af"
        
    strings:
        $ = "C:\\Users\\Dead Snake\\source\\repos\\cheex" ascii fullword
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        
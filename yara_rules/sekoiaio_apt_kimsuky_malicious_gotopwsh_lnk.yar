rule sekoiaio_apt_kimsuky_malicious_gotopwsh_lnk {
    meta:
        id = "cfe9adf5-2c06-4d04-8006-c4eea0dab549"
        version = "1.0"
        description = "Detects malicious LNK used by Kimsuky"
        source = "Sekoia.io"
        creation_date = "2023-09-11"
        classification = "TLP:CLEAR"
        
    strings:
        $ = {67 00 6f 00 74 00 6f 00 26 00 70 00 5e 00 6f 00 77 00 5e 00 65 00 5e 00 72 00 73 00 5e 00 68 00 65 00 5e 00 6c 00 5e 00 6c}
        
    condition:
        uint32be(0) == 0x4c000000 and all of them
}
        
rule sekoiaio_apt_darkpink_sample {
    meta:
        id = "91b4c64a-7622-4f03-bd3f-9fe56f01dfbe"
        version = "1.0"
        description = "Detects two parts of cmd.exe /c "
        author = "Sekoia.io"
        creation_date = "2023-06-05"
        classification = "TLP:CLEAR"
        hash = "8dc3f6179120f03fd6cb2299dbc94425451d84d6852b801a313a39e9df5d9b1a"
        
    strings:
        $cmd_xor_part_1 = {DF 00 A1 00 E4 00 F0 00 4B 00 3A 00 D1 00 C4 00}
        $cmd_xor_part_2 = {bc 00 cc 00 80 00 d0 00 64 00 59 00 F1 00 E6 00 FD 00 83 00 C6}
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize <1MB and
        all of them
}
        
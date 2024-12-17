rule sekoiaio_apt_ta410_flowcloud_loader {
    meta:
        id = "0a11dfa0-5a59-477b-baf6-6a777d020860"
        version = "1.0"
        description = "Detects FlowCloud Loader"
        author = "Sekoia.io"
        creation_date = "2024-05-27"
        classification = "TLP:CLEAR"
        
    strings:
        $decryption_function = {8A C8 80 C1 26 32 D1 30 14 38}
        $derivation_key = {6B 04 00 00 F7 ?? 81 c2 a8 01 00 00}
        
        $new_pattern_1 = {50 33 c0 58 74 01 e8}
        $new_pattern_2 = {89 44 24 fc 58 8D 64
        24 fc 81 fc 00 10 00
        00 77 06 81 c4 ?? ??
        ?? ?? 8B 44 24 FC}
        $patch_bytes = {68 78 56 34 12 C3 90 90 90 90 90 00}
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 4MB and 2 of them
}
        
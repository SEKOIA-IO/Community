rule sekoiaio_kimsuky_konni_dll {
    meta:
        id = "6a20c492-e932-41bd-ac4a-01d35bfb0c49"
        version = "1.0"
        description = "Rule based on structure offset and file extension"
        source = "Sekoia.io"
        creation_date = "2022-09-12"
        classification = "TLP:CLEAR"
        
    strings:
        $ext_1 = ".zip" wide ascii fullword
        $ext_2 = ".cab" wide ascii fullword
        $ext_3 = ".rar" wide ascii fullword
        $ext_4 = ".ini" wide ascii fullword
        $ext_5 = ".dat" wide ascii fullword
        
        $offset_structure_1 = { 8d ?? 08 02 00 00 } //offset 0x208
        $offset_structure_2 = { 8d ?? 10 04 00 00 } //offset 0x410
        $offset_structure_3 = { 8d ?? 18 06 00 00 } //offset 0x618
        $offset_structure_4 = { 8d ?? 20 08 00 00 } //offset 0x820
        $offset_structure_5 = { 8d ?? 28 0a 00 00 } //offset 0xa28
        $offset_structure_6 = { 89 ?? f8 11 00 00 } //offset 0x11f8
        $offset_structure_7 = { 8d ?? fc 11 00 00 } //offset 0x11fc
        $offset_structure_8 = { 89 ?? 0c 12 00 00 } //offset 0x120c
        $offset_structure_9 = { 89 ?? 10 12 00 00 } //offset 0x1210
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 11MB and all of them
}
        
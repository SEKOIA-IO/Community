rule sekoiaio_apt_konni {
    meta:
        id = "6a20c492-e932-41bd-ac4a-01d35bfb0c49"
        version = "1.0"
        description = "Rule based on structure offsets and file extension"
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
        $url = "%s/dn.php?name=%s&prefix=%s" wide
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 3MB and 3 of ($ext_*) and all of ($offset_structure_*) and $url
}
        
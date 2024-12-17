rule sekoiaio_tool_petitpotato {
    meta:
        id = "72808202-a124-478e-bc60-59d35824b948"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-08-23"
        classification = "TLP:CLEAR"
        
    strings:
        $s2 = "set_FileName" ascii wide
        $s3 = "VarFileInfo" ascii wide
        $s4 = "PetitPotato.exe" ascii wide
        $s5 = "0.0.0.0" ascii wide
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 4MB and 
        all of them
}
        
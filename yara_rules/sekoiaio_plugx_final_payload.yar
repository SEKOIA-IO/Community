import "pe"
        
rule sekoiaio_plugx_final_payload {
    meta:
        id = "a4047324-81a7-4c17-be84-c0fa479d2f89"
        version = "1.0"
        description = "Detects encrypted plugx config with a specific size"
        source = "Sekoia.io"
        creation_date = "2023-07-04"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = {30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46 88 13 00 00 60 ea 00 00 ?? ?? ?? ?? 00 00 00 00}
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 8MB and 
        for any i in (0..pe.number_of_sections-1) : 
        (
            pe.sections[i].name == ".data"
            and $s1 in (pe.sections[i].raw_data_offset..pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size)
        )
}
        
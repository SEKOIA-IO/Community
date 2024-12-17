rule sekoiaio_tool_masky_strings {
    meta:
        id = "542670ee-9f2e-4148-853d-a3f055bd584c"
        version = "1.0"
        description = "Detects Masky tool"
        author = "Sekoia.io"
        creation_date = "2022-08-23"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "caa1aa2e-8a2a-4f98-bc51-b7cf10663fa9" ascii
        $s2 = "Masky" ascii
        $s3 = "\\Windows\\Temp\\" wide
        $s4 = "Length must be non-negative" wide
        $s5 = "CSP does not contain a private key" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        4 of them or $s1
}
        
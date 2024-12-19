rule tool_sy_runas {
    meta:
        id = "cb1f3707-6716-49b5-9fe0-45c5baf2e491"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-08-23"
        classification = "TLP:CLEAR"
        author = "Sekoia.io"
        
    strings:
        $s1 = "Sy_Runas.exe" ascii wide
        $s2 = "password *.exe" ascii wide
        $s3 = "This tools just work on webshell" ascii wide
        $s4 = "Code By slls124@gmail.com" ascii wide
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 4MB and
        all of them
}
        
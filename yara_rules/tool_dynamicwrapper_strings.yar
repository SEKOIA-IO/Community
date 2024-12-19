rule tool_dynamicwrapper_strings {
    meta:
        id = "bbfad0a8-8b86-47c7-bf70-0a3f6859d64b"
        version = "1.0"
        description = "Detects DynamicWrapperX"
        author = "Sekoia.io"
        creation_date = "2023-12-01"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Software\\Classes\\DynamicWrapperX" ascii
        $ = "DllRegisterServer" ascii
        $ = "GoLink, GoAsm" ascii
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 100KB and
        all of them
}
        
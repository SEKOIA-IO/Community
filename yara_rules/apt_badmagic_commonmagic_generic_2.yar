rule apt_badmagic_commonmagic_generic_2 {
    meta:
        id = "c6a16ecc-e00a-4756-b603-f6c85e4f4220"
        version = "1.0"
        description = "Detects CommonMagic related implants"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "\\CommonCommand\\" ascii wide
        $ = "\\\\.\\pipe\\PipeMd" ascii wide fullword
        $ = "\\\\.\\pipe\\PipeDtMd" ascii wide fullword
        $ = "\\\\.\\pipe\\PipeCrDtMd" ascii wide fullword
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        2 of them
}
        
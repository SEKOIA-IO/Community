rule apt_badmagic_commonmagic_main {
    meta:
        id = "99983df5-89d6-4fac-81e6-16e5ab20bde3"
        version = "1.0"
        description = "Detects CommonMagic related implants"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "graph.microsoft.com" ascii wide
        $ = "children?select=name,size" ascii wide fullword
        $ = "\\\\.\\pipe\\PipeCrDtMd" ascii wide fullword
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        all of them
}
        
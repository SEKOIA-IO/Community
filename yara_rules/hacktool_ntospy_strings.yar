rule hacktool_ntospy_strings {
    meta:
        id = "c3281666-6a31-4718-a9c0-82944c6fdcb0"
        version = "1.0"
        description = "Detects Ntospy based on strings"
        author = "Sekoia.io"
        creation_date = "2023-12-05"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "NPGetCaps"
        $ = "NPLogonNotify"
        $ = {43 00 3A 00 5C 00 [10-150] 00 2E 00 6D 00 73 00 75}
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 300KB and
        all of them
}
        
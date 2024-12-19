rule hacktool_ntdsdumpex_strings {
    meta:
        id = "9a0fe20a-49e9-4aaf-8f0e-d51800e0a6e0"
        version = "1.0"
        description = "Detects NTDSDumpEx based on strings"
        author = "Sekoia.io"
        creation_date = "2022-02-25"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Example : ntdsdumpex.exe -r" ascii wide
        $ = "[x]can not open output file %s for write." ascii wide
        $ = "[+]dump completed in %.3f seconds." ascii wide
        $ = "[+]total %d entries dumped,%d" ascii wide
        $ = "[x]can not get PEK!" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 200KB and
        3 of them
}
        
rule apt_luckymouse_rshell_strings {
    meta:
        id = "89f18013-ea3e-440f-821e-cef102a43b7b"
        version = "1.0"
        description = "Detects LuckyMouse RShell Mach-O implant"
        author = "Sekoia.io"
        creation_date = "2022-08-05"
        classification = "TLP:CLEAR"
        
    strings:
        $ = { 64 69 72 00 70 61 74 68
        00 64 6F 77 6E 00 72 65
        61 64 00 75 70 6C 6F 61
        64 00 77 72 69 74 65 00
        64 65 6C }
        $ = { 6C 6F 67 69 6E 00 68 6F
        73 74 6E 61 6D 65 00 6C
        61 6E 00 75 73 65 72 6E
        61 6D 65 00 76 65 72 73
        69 6F 6E }
        
    condition:
        (uint32be(0) == 0xCFFAEDFE or uint16be(0) == 0x4d5a) and 
        filesize < 300KB and
        all of them
}
        
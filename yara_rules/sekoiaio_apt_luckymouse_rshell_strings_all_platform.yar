rule sekoiaio_apt_luckymouse_rshell_strings_all_platform {
    meta:
        id = "e79a5ee1-96b3-4643-ab11-0b1095e96488"
        version = "1.0"
        description = "Detects LuckyMouse RShell Mach-O implant"
        source = "Sekoia.io"
        creation_date = "2022-08-05"
        classification = "TLP:CLEAR"
        
    strings:
        $ = { 6C 6F 67 69 6E 00 68 6F
        73 74 6E 61 6D 65 00 6C
        61 6E 00 75 73 65 72 6E
        61 6D 65 00 76 65 72 73
        69 6F 6E }
        
    condition:
        filesize < 1MB and
        all of them
}
        
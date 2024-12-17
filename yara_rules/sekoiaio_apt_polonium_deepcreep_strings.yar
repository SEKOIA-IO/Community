rule sekoiaio_apt_polonium_deepcreep_strings {
    meta:
        id = "b04af229-2bea-4ee8-9e17-8e4befa06e3a"
        version = "1.0"
        description = "Tries to detect POLONIUM's DeepCreep implant"
        author = "Sekoia.io"
        creation_date = "2022-10-12"
        classification = "TLP:CLEAR"
        
    strings:
        $ = ";Invoke-Expression -Command '$shortcut =" ascii wide
        $ = "CreateShortcut($c1" ascii wide
        $ = "svchostdp.exe" ascii wide
        $ = "HNlIC91IA==" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 3MB and
        3 of them
}
        
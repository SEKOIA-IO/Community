rule apt_polonium_megacreep_strings {
    meta:
        id = "927c5fd6-0574-43bf-8db9-6ecc328estrin56c7"
        version = "1.0"
        description = "Tries to detect POLONIUM's MegaCreep implant"
        author = "Sekoia.io"
        creation_date = "2022-10-12"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[#!#]" ascii wide
        $ = "[$$%$$]" ascii wide
        $ = ".e##x##e" ascii wide
        $ = "WHLib.dll" ascii wide
        $ = "TestService.txt" ascii wide
        $ = "X = Stop" ascii wide
        $ = "Sess.dll" ascii wide
        $ = "filepathOnTarget" ascii wide
        $ = "FileNameOnMega" ascii wide
        $ = "Missing Parameter.. Format of command:" ascii wide
        $ = "Your Old K##E##Y is Wronge" ascii wide
        $ = "Your Upgrage Is Success" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 2MB and
        3 of them
}
        
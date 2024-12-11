rule sekoiaio_hacktool_defendercontrol_strings {
    meta:
        id = "c6587a46-5f9b-4bf0-9231-9d2505293557"
        version = "1.0"
        description = "Detects DefenderControl based on strings"
        source = "Sekoia.io"
        creation_date = "2022-03-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "www.sordum.org All Rights Reserved." wide
        $ = "dControl.exe" wide
        $ = "By BlueLife" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 600KB and
        all of them
}
        
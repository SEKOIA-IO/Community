rule apt_apt41_keyplug_dropper {
    meta:
        id = "b6740371-c4c3-437e-8235-0bd4f7b9c3f5"
        version = "1.0"
        description = "Detects a dropper used by keyplug"
        author = "Sekoia.io"
        creation_date = "2024-06-12"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "C:\\ProgramData\\pfm.ico" wide
        $ = "C:\\\\ProgramData\\\\pfm.ico" wide
        $ = "67f8de349abc5ghi" wide
        $ = "3abc64597f8diegh" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 2MB and
        any of them
}
        
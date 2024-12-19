rule apt_badmagic_commonmagic_usbstealer {
    meta:
        id = "37d5becc-f1c3-4400-bc10-cd6036d4dbb1"
        version = "1.0"
        description = "Detects CommonMagic related implants"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "\\\\.\\pipe\\PipeDtMd" ascii wide fullword
        $ = "State USB" ascii wide
        $ = "DefaultNameDevice" ascii wide
        $ = "SerialNumber" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        all of them
}
        
rule sekoiaio_apt_kimsuky_validator_strings {
    meta:
        id = "e055f2d4-8318-4342-812e-0f621d7886b4"
        version = "1.0"
        description = "Detects Kimsuky validator"
        source = "Sekoia.io"
        creation_date = "2024-06-11"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "%s%sc %s >%s 2>&1" wide
        $ = "%s%sc %s 2>%s" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        all of them
}
        
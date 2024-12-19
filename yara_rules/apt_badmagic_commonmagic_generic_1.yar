rule apt_badmagic_commonmagic_generic_1 {
    meta:
        id = "0b328771-f674-4606-bb30-d20d07c67832"
        version = "1.0"
        description = "Detects CommonMagic related implants"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "\\CommonCommand\\Clean\\"
        $ = "\\CommonCommand\\Overall\\"
        $ = "\\CommonCommand\\Other\\"
        $ = "\\CommonCommand\\Other\\*"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        all of them
}
        
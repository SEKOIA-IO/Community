rule apt_oilrig_odagent_strings {
    meta:
        id = "1c5c0eb5-7c6f-4a34-b2e2-4a7c6d7030d6"
        version = "1.0"
        description = "Detects ODAgent malware based on strings"
        author = "Sekoia.io"
        creation_date = "2023-12-20"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "application/x-www-form-urlencoded" ascii wide
        $ = "dly>" ascii wide
        $ = "DELETE" ascii wide
        $ = "nok!" ascii wide
        $ = ".c:/content" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 5MB and
        all of them
}
        
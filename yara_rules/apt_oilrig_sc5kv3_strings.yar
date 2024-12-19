rule apt_oilrig_sc5kv3_strings {
    meta:
        id = "885ea13b-47b0-4a6d-8136-9b31abc9064a"
        version = "1.0"
        description = "Detects SC5kv3 malware based on strings"
        author = "Sekoia.io"
        creation_date = "2023-12-20"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "no-reply this email!" ascii wide
        $ = "The serial is " ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 5MB and
        all of them
}
        
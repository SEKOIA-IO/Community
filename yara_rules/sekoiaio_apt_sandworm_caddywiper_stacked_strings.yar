rule sekoiaio_apt_sandworm_caddywiper_stacked_strings {
    meta:
        id = "7750c4b6-5781-4b1c-8200-cbce9f18aa56"
        version = "2.0"
        description = "Detects stacked strings used in the wiper."
        author = "Sekoia.io"
        creation_date = "2022-04-06"
        classification = "TLP:CLEAR"
        
    strings:
        $ =  { C6 45 ?? 6E
        C6 45 ?? 65
        C6 45 ?? 74
        C6 45 ?? 61
        C6 45 ?? 70
        C6 45 ?? 69
        C6 45 ?? 33
        C6 45 ?? 32
        C6 45 ?? 2E
        C6 45 ?? 64
        C6 45 ?? 6C
        C6 45 ?? 6C }
        $ = {  C6 45 ?? 44
        C6 45 ?? 65
        C6 45 ?? 76
        C6 45 ?? 69
        C6 45 ?? 63
        C6 45 ?? 65
        C6 45 ?? 49
        C6 45 ?? 6F
        C6 45 ?? 43
        C6 45 ?? 6F
        C6 45 ?? 6E
        C6 45 ?? 74
        C6 45 ?? 72
        C6 45 ?? 6F
        C6 45 ?? 6C }
        $ = { C6 45 ?? 5C
        C6 45 ?? 00
        C6 45 ?? 5C
        C6 45 ?? 00
        C6 45 ?? 2E
        C6 45 ?? 00
        C6 45 ?? 5C
        C6 45 ?? 00
        C6 45 ?? 50
        C6 45 ?? 00
        C6 45 ?? 48
        C6 45 ?? 00
        C6 45 ?? 59
        C6 45 ?? 00
        C6 45 ?? 53
        C6 45 ?? 00
        C6 45 ?? 49
        C6 45 ?? 00
        C6 45 ?? 43
        C6 45 ?? 00
        C6 45 ?? 41
        C6 45 ?? 00
        C6 45 ?? 4C
        C6 45 ?? 00
        C6 45 ?? 44
        C6 45 ?? 00
        C6 45 ?? 52
        C6 45 ?? 00
        C6 45 ?? 49
        C6 45 ?? 00
        C6 45 ?? 56
        C6 45 ?? 00
        C6 45 ?? 45 }
        
    condition:
        uint16be(0) == 0x4d5a and 2 of them
}
        
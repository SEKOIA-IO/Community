rule tool_swor {
    meta:
        id = "75ce2ed7-2972-4e04-98dc-451acf80c842"
        version = "1.0"
        description = "Detects swor"
        author = "Sekoia.io"
        creation_date = "2024-09-09"
        classification = "TLP:CLEAR"
        hash = "d3f92b3349109fc6de26f5e40800fec15308c27fa4fe81fe42af5030637a3a63"
        
    strings:
        $old_sword_s1 = "Failed to open payload file: "
        $old_sword_s2 = "Failed to open config file: "
        $sword_s1 = "open encrypted file error: "
        $sword_s2 = "open config file error: "
        $enum_calendar = "EnumCalendarInfo"
        
    condition:
        uint16be(0) == 0x4d5a and
        $enum_calendar and 
        (2 of ($old_sword_s*) or 2 of ($sword_s*)) and
        filesize <1MB and 
        true
}
        
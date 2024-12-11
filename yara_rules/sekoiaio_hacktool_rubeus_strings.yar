rule sekoiaio_hacktool_rubeus_strings {
    meta:
        id = "048cab99-c288-44c2-9dc6-74eed02ef8f5"
        version = "1.0"
        description = "Detects Rubeus based on strings"
        source = "Sekoia.io"
        creation_date = "2022-02-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "includeComputerAccounts" ascii
        $ = "passwordsOutfile" ascii
        $ = "monitorIntervalSeconds" ascii
        $ = "displayNewTickets" ascii
        $ = "658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        4 of them
}
        
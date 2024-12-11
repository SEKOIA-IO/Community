rule sekoiaio_tool_advancedrun_strings {
    meta:
        id = "842a996e-0cf2-485f-9d3c-ccbd40c9ab6c"
        version = "1.0"
        description = "Detects AdvancedRun strings"
        source = "Sekoia.io"
        creation_date = "2024-09-06"
        classification = "TLP:CLEAR"
        hash = "a1d50ebe6124584f32de0625475cdb74"
        
    strings:
        $ = "nirsoft.net" wide
        $ = "Another logged-in user" wide
        $ = "Choose config file to save" wide
        $ = "AdvancedRun" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and
        all of them and filesize < 1MB
}
        
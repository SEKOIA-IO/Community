rule sekoiaio_tool_yasso_strings {
    meta:
        id = "31ec7510-6770-4fde-b835-e8b12f8f2b30"
        version = "1.0"
        description = "Detects Yasso based on strings"
        source = "Sekoia.io"
        creation_date = "2023-06-21"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Yasso/cmd.setting"
        $ = "Yasso/cmd.Client"
        $ = "Yasso/cmd.IdentifyResult"
        $ = "Yasso/cmd.RespLab"
        $ = "Go build ID"
        
    condition:
        uint16be(0) == 0x4d5a and 
        filesize > 15MB and filesize < 20MB and
        all of them
}
        
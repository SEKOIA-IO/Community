rule sekoiaio_tool_tacticalrmm_installer_strings {
    meta:
        id = "c4a0ba33-b458-4c2a-abfa-4c33481d6491"
        version = "1.0"
        description = "Detects TacticalRMM installer"
        author = "Sekoia.io"
        creation_date = "2024-05-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "TacticalRMMInstaller" ascii
        $ = "tacticalagent-" ascii
        $ = "tactical/go" ascii
        $ = "tacticalrmm." ascii
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize > 3MB and filesize < 8MB and
        3 of them
}
        
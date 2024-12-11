rule sekoiaio_tool_lsass_dump_strings {
    meta:
        id = "bf024dc6-a1c8-4c3f-9bf8-8d246c129639"
        version = "1.0"
        description = "Detects Lsass dump based on strings"
        source = "Sekoia.io"
        creation_date = "2024-09-09"
        classification = "TLP:CLEAR"
        hash = "f4540f42902c068b9290239729c45324"
        
    strings:
        $ = "[SUCCESS] Successfully dumped core LSASS information for PID:"
        $ = "[SUCCESS] All data dumped to "
        $ = "[ERROR] Unable to dump process"
        
    condition:
        uint16be(0) == 0x4d5a and
        3 of them
}
        
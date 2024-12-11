rule sekoiaio_tool_paexec_strings {
    meta:
        id = "c48b897c-0d88-4fa9-b64b-0e14a38a62d7"
        version = "1.0"
        description = "Detects PAExec based on strings"
        source = "Sekoia.io"
        creation_date = "2022-09-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "\\\\%s\\%s\\PAExec_Move%u.dat" wide
        $ = "PAExec_Move%u.dat" wide
        $ = "Usage: PAExec [\\\\computer[,computer2[,...]]" wide
        $ = "PAExec returning exit code %d" wide
        
    condition:
        uint16be(0) == 0x4d5a and 3 of them
        and filesize < 500KB
}
        
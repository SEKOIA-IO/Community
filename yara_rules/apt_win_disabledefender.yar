import "pe"
        
rule apt_win_disabledefender {
    meta:
        id = "a7b124ab-4c9d-47c0-a59e-211cc713b9b3"
        version = "1.0"
        description = "detects strings and imphash"
        author = "Sekoia.io"
        creation_date = "2022-09-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Restarting with privileges"
        $ = "Windows defender is currently ACTIVE"
        $ = "Windows defender is currently OFF"
        $ = "Disabled windows defender"
        $ = "Failed to disable defender..."
        
    condition:        4 of them or pe.imphash() == "74a6ef9e7b49c71341e439022f643c8e"
}
        
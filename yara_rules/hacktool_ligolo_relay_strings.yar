rule hacktool_ligolo_relay_strings {
    meta:
        id = "1e32f2e5-b66b-4b55-9dd4-1402b2f627ed"
        version = "1.0"
        description = "Detects Ligolo Relay based on strings"
        author = "Sekoia.io"
        creation_date = "2022-02-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "ligolo/cmd/localrelay"
        $ = "main.LigoloRelay.Start"
        $ = "main.LigoloRelay.startRelayHandler"
        $ = "main.LigoloRelay.startLocalHandler"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize > 2MB and filesize < 5MB and
        3 of them
}
        
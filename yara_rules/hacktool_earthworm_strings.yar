rule hacktool_earthworm_strings {
    meta:
        id = "6c9b0225-8c41-49f9-9745-245bc7ef942f"
        version = "1.0"
        description = "Detects Mac/Win/Linux EarthWorm based on strings"
        author = "Sekoia.io"
        creation_date = "2022-02-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "the read url is %s"
        $ = "--> %3d <-- (close)used tunnel %d , unused tunnel %d"
        $ = "ssocksd 0.0.0.0:%d <--[%4d usec]--> socks server"
        $ = "could not create one way tunnel"
        
    condition:
        (uint32be(0) == 0x7f454c46 
         or uint16be(0) == 0x4d5a
         or uint32be(0) == 0xcffaedfe
        ) and filesize < 100KB and
        3 of them
}
        
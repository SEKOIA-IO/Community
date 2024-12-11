rule sekoiaio_tool_rsockstun_strings {
    meta:
        id = "94d8cb39-3421-441c-8404-62a591b86912"
        version = "1.0"
        description = "Detects Rsockstun based on strings"
        source = "Sekoia.io"
        creation_date = "2023-12-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "main.connectviaproxy"
        $ = "main.connectForSocks"
        $ = "main.listenForClients"
        $ = "main.listenForSocks"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 10MB and
        all of them
}
        
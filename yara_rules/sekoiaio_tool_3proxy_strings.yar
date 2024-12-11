rule sekoiaio_tool_3proxy_strings {
    meta:
        id = "daf6cd97-8033-4bfd-88b5-41c06eb417b0"
        version = "1.0"
        description = "Detects 3proxy based on strings"
        source = "Sekoia.io"
        creation_date = "2024-03-14"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "of 3proxy-"
        $ = "-pPORT - service port to accept connections"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 500KB and
        all of them
}
        
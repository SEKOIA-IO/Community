rule sekoiaio_tool_koblas_server_strings {
    meta:
        id = "ebd891da-69dd-474c-9e08-63d0b4cc654e"
        version = "1.0"
        description = "Detects Koblas server"
        author = "Sekoia.io"
        creation_date = "2024-05-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "sent {sent} bytes and received {received} bytes" wide ascii
        $ = "connection denied" ascii
        $ = "loaded {} users" ascii
        $ = "listening on {}:{} for incoming connections" ascii
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        3 of them
}
        
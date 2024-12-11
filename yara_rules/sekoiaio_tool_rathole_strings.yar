rule sekoiaio_tool_rathole_strings {
    meta:
        id = "39d11285-a3bf-46c3-901d-ab46601a9066"
        version = "1.0"
        description = "Detects RATHole based on strings"
        source = "Sekoia.io"
        creation_date = "2024-05-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "rathole\\src\\" ascii
        $ = "\\\\?\\\\\\?\\UNC\\" wide
        $ = "rathole::" ascii
        $ = "src/server.rs"
        $ = "`[server]` or `[client]"
        
    condition:
        ( uint32be(0) == 0x7f454c46 or 
          uint16be(0) == 0x4d5a or 
          uint32be(0) == 0xfeedface or 
          uint32be(0) == 0xfeedfacf or 
          uint32be(0) ==  0xcafebabe or
          uint32be(0) ==  0xCFFAEDFE) and
        3 of them
}
        
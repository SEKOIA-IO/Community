rule sekoiaio_tool_inswor_strings {
    meta:
        id = "99aaad33-510a-41b9-9022-800588c18d6d"
        version = "1.0"
        description = "Detects In-Swor based on strings"
        author = "Sekoia.io"
        creation_date = "2024-09-09"
        classification = "TLP:CLEAR"
        hash = "c393128a143b2a3397100b4a30c75112"
        
    strings:
        $ = "open encrypted file error:" ascii
        $ = "open config file error:" ascii
        $ = "payload.ini" ascii
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        
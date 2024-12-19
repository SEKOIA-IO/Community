rule tool_scanline_strings {
    meta:
        id = "65677b81-d077-4d01-8398-cbb06ce49edf"
        version = "1.0"
        description = "Detects scanline (non-packed)"
        author = "Sekoia.io"
        creation_date = "2024-09-06"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Resolve IP addresses to hostnames"
        $ = "Randomize IP and port scan order"
        $ = "?bhijnprsT"
        $ = "sl -bht"
        
    condition:
        uint16be(0) == 0x4d5a and 3 of them
}
        
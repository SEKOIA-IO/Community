rule sekoiaio_tool_sharpefspotato_strings {
    meta:
        id = "4286c72b-c0b9-4d2c-9847-68fc39ed4894"
        version = "1.0"
        description = "Detects SharpEfsPotato based on strings"
        source = "Sekoia.io"
        creation_date = "2023-06-20"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Program to launch (default cmd.exe)" wide
        $ = "[!] Cannot perform interception, necessary privileges missing." wide
        $ = "[!] Failed to created impersonated process with token:" wide
        $ = "No authenticated interception took place, exploit failed"
        
    condition:
        uint16be(0) == 0x4d5a and 3 of them
}
        
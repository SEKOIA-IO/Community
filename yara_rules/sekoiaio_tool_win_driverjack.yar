rule sekoiaio_tool_win_driverjack {
    meta:
        id = "08bc0fe8-38f1-4c73-99c8-2659b4a55815"
        version = "1.0"
        source = "Sekoia.io"
        creation_date = "2024-09-11"
        classification = "TLP:CLEAR"
        hash = "649fc12915bdcdebbc3798a8ad0b9b32"
        reference = "https://github.com/klezVirus/DriverJack/blob/master/DriverJack"
        
    strings:
        $ = "(*) Decrypting %llu bytes of file content using key '%s' of length %u..."
        $ = "(*) Modifying file %s in mapped drive..."
        $ = "(*) Checking file %s in mapped drive..."
        $ = "(-) CreateProcess failed '%s' (%08x)."
        $ = "(*) Mounted Drive Letter: %s"
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        
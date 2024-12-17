rule sekoiaio_tool_runpeinmemory_strings {
    meta:
        id = "64129ab0-b599-4760-ab21-20c475c2c07f"
        version = "1.0"
        description = "Detects standard implementation of RunPEInMemory"
        author = "Sekoia.io"
        creation_date = "2024-05-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[+] Fix Import Address Table"
        $ = "[+] Relocation Fixed."
        $ = "[+] File %s isn't a PE file."
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 500KB and
        all of them
}
        
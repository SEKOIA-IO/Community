rule tool_juicypotatong_strings {
    meta:
        id = "4634251b-ea41-4f58-aabd-db83ccf4edaa"
        version = "1.0"
        description = "Detects JuicyPotatoNG"
        author = "Sekoia.io"
        creation_date = "2023-06-20"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[!] CryptStringToBinaryW failed with error code %d" ascii
        $ = "-b : Bruteforce all CLSIDs. !ALERT:" ascii
        $ = "[-] CreateProcessWithTokenW Failed to create proc: %d" ascii
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        
rule tool_edrsandblast_cli_strings {
    meta:
        id = "baf3c68a-1d28-464e-8240-28cc66c8c151"
        version = "1.0"
        description = "Detects EDRSandblast CLI strings"
        author = "Sekoia.io"
        creation_date = "2024-01-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[!] LSASS dump might fail if RunAsPPL" wide
        $ = "[!] You did not provide at least one option between" wide
        $ = "[+] Detecting userland hooks in all loaded DLLs" wide
        $ = "[+] Saving them to the CSV file" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        4 of them
}
        
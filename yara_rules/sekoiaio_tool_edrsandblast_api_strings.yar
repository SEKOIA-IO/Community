rule sekoiaio_tool_edrsandblast_api_strings {
    meta:
        id = "8a5dc171-dce8-4b5a-96e9-53dd1855e8c1"
        version = "1.0"
        description = "Detects EDRSandblast API strings"
        author = "Sekoia.io"
        creation_date = "2024-01-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[!] Required driver file not present at" wide
        $ = "[!] New uninstall / install attempt failed" wide
        $ = "[!] Kernel offsets are missing from the CSV" wide
        $ = "[+] Downloading wdigest offsets from the MS Symbol Server" wide
        $ = "[+] Check if EDR callbacks are registered on process" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        4 of them
}
        
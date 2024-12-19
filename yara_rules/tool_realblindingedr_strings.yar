rule tool_realblindingedr_strings {
    meta:
        id = "505dcbee-ae37-47c1-a322-2c52d10e68d7"
        version = "1.0"
        description = "Detects RealBlindingEDR based on strings"
        author = "Sekoia.io"
        creation_date = "2024-09-11"
        classification = "TLP:CLEAR"
        hash = "cb6219e2b6577b8d4a18114d595e10d7"
        hash = "d0a251709c24a8f4c26d456dea22d90f"
        
    strings:
        $ = "Unload Driver Error 1"
        $ = "Failed to create pipe. Error %d"
        $ = "icacls \"%s\" /grant Everyone:(F)"
        $ = "Register MiniFilter Callback driver:"
        $ = "The driver's certificate has been revoked,"
        $ = "[Success] Killed %s(%s)."
        $ = "ntoskrnl.exe base address not found."
        
    condition:
        uint16be(0) == 0x4d5a and
        4 of them
}
        
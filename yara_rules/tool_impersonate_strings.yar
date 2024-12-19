import "pe"
        
rule tool_impersonate_strings {
    meta:
        id = "2ab345a2-9366-4673-b398-a59ba6954af5"
        version = "1.0"
        description = "Detects Impersonate"
        author = "Sekoia.io"
        creation_date = "2024-07-24"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[*] Listing available tokens"
        $ = "[ID: %2d][SESSION: %d][INTEGRITY: %-6ws][%-18ws][%-22ws] User: %ws"
        $ = "[*] Impersonating %ws"
        $ = "[!] Impersonation failed error: %d"
        $ = "[*] Adding user %ls on %ls"
        $ = "[!] Add user failed with error: %d"
        $ = "[*] Adding user %ws to domain group %ws"
        $ = "[!] Add user in domain %ws failed with error: %d"
        $ = "[!] Couldn't change token session id (error: %d)"
        
    condition:
        uint16be(0) == 0x4d5a and
        3 of them or pe.imphash() == "e14ce763114276674e22b7b8b637bd4b"
}
        
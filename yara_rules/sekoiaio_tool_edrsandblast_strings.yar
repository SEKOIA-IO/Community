rule sekoiaio_tool_edrsandblast_strings {
    meta:
        id = "7059b89c-80b5-4768-b3eb-02f173f628b0"
        version = "1.0"
        description = "Detects EDRSandblast strings"
        source = "Sekoia.io"
        creation_date = "2024-01-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[!] Cred Guard bypass failed: obtained invalid" wide
        $ = "[!] Cred Guard bypass non fatal error:" wide
        $ = "[+] Successfully overwrote wdigest's g_fParameter_UseLogonCredential" wide
        $ = "[!] ERROR: could not allocate memory for the handl" wide
        $ = "[+] [ProcessProtection] Found the handle of the current" wide
        $ = "[+] [ProcessProtection] Found self process EPROCCES struct at" wide
        $ = "ETW Threat Intel ProviderEnableInfo address could not be found." wide
        $ = "The ETW Threat Intel provider was successfully" wide
        $ = "[+] [NotifyRountines]" wide
        $ = "[callback addr: 0x" wide
        $ = "EDR / security products driver(s)" wide
        $ = "Object callback offsets not loaded ! Aborting..." wide
        $ = "No more space to store object callbacks !!" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        3 of them
}
        
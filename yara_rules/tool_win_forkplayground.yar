rule tool_win_forkplayground {
    meta:
        id = "ec9af403-7647-447d-af17-c6931363a166"
        version = "1.0"
        description = "Detect the ForkPlayground malware"
        author = "Sekoia.io"
        creation_date = "2023-02-28"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Failed to open dump file %s with the last error %i."
        $ = "Successfully dumped process %i to %s"
        $ = "ForkPlayground"
        $ = "Second attempt at taking a snapshot of the target failed. It is likely that there is a difference in process privilege or the handle was stripped."
        $ = "Failed to take a snapshot of the target process. Attempting to escalate debug privilege..."
        $ = "Failed to escalate debug privileges, are you running ForkDump as Administrator"
        
    condition:
        uint16(0)==0x5A4D and 1 of them
}
        
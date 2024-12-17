rule sekoiaio_tool_edrsandblast_kernelcallbacks {
    meta:
        id = "74cf4444-5bd6-4167-930a-5dbf2e529f92"
        version = "1.0"
        description = "Detects EDRSandblast KernelCallbacks strings"
        author = "Sekoia.io"
        creation_date = "2024-11-25"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[+] '%s' service ACL configured to for Everyone" wide
        $ = "%s callback of EDR driver \"%s\" [callback addr: 0x%I64x" wide
        $ = "[!] Could not resolve %s kernel module's address" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 3MB and
        3 of them
}
        
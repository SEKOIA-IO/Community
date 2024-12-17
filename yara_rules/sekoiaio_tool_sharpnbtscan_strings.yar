rule sekoiaio_tool_sharpnbtscan_strings {
    meta:
        id = "e9d28dcb-b4b1-4d66-b225-ed0925f307d9"
        version = "1.0"
        description = "Detects SharpNBTScan based on strings"
        author = "Sekoia.io"
        creation_date = "2024-09-09"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[+]Udp client will stop in 10 s ..." ascii wide
        $ = "[*]Stop udp client ..." ascii wide
        $ = "[*]Start udp client ..." ascii wide
        $ = "[+] ip range {0} - {1} " ascii wide
        
    condition:
        uint32be(0) == 0x5A4D and
        all of them
}
        
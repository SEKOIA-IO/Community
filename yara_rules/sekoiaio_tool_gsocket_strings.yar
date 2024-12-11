rule sekoiaio_tool_gsocket_strings {
    meta:
        id = "55fb2f2b-1074-4b6d-9113-48eaeb0e1e27"
        version = "1.0"
        description = "Detects Gsocket based on strings"
        source = "Sekoia.io"
        creation_date = "2024-06-10"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "proxy. It allows multiple gs-netcat clients to (securely) relay"
        $ = "GS-NETCAT(1)            General Commands Manual          GS-NETCAT(1)"
        $ = "-T      Use TOR. The gs-netcat tool will connect via TOR to the GSRN."
        $ = "-D      Daemon & Watchdog mode. Start gs-netcat as a background process"
        $ = "gs-netcat [-rlgvqwCTSDiu] [-s secret] [-k keyfile] [-L logfile] [-d IP]"
        $ = "The gs-netcat utility is a re-implementation of netcat."
        
    condition:
        (
            uint32be(0) == 0x7f454c46 or 
            uint16be(0) == 0x4d5a or 
            uint32be(0) == 0xfeedface or 
            uint32be(0) == 0xcffaedfe or 
            uint32be(0) == 0xcafebabe
        ) and
        filesize > 2MB and filesize < 6MB and
        2 of them
}
        
rule tool_dogtunnel_strings {
    meta:
        id = "00705613-6367-454f-b3f2-1e2b0a52459c"
        version = "1.0"
        description = "Detects Dog Tunnel based on strings"
        author = "Sekoia.io"
        creation_date = "2024-03-14"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "pipe.(*UDPMakeSession).doAndWait"
        $ = "ikcp.ikcp_parse_fastack"
        $ = "pipe.ListenWithSetting"
        $ = "pipe.DialTimeoutWithSetting"
        $ = "common.ReadUDP"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) 
        and all of them and filesize < 10MB
}
        
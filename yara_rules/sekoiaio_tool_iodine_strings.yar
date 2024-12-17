rule sekoiaio_tool_iodine_strings {
    meta:
        id = "029766cc-80fb-423d-adc5-8867c438c5d3"
        version = "1.0"
        description = "Detects iodine based on strings"
        author = "Sekoia.io"
        creation_date = "2024-02-02"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Sending DNS queries for %s to %s"
        $ = "No tun devices found, trying utun"
        $ = "iodine IP over DNS tunneling client"
        $ = "topdomain is the FQDN that is delegated to the tunnel endpoint."
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
         filesize < 1MB and
        3 of them
}
        
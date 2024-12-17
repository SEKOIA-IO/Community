rule sekoiaio_hacktool_dnscat2_strings {
    meta:
        id = "9655cdd7-c7fe-4033-bdd9-bdfcfd2bf827"
        version = "1.0"
        description = "Detects DNSCat2 based on strings"
        author = "Sekoia.io"
        creation_date = "2022-02-25"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Creating a exec('%s') session!"
        $ = "RROR parsing --dns"
        $ = "Got a ping request! Responding!"
        $ = "[Tunnel %d] Received %zd bytes"
        $ = "[Tunnel %d] connection to %s:%d"
        $ = "You'll need to use --dns server=<server>"
        $ = "Setting delay between packets to %dms"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        3 of them
}
        
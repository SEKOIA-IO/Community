rule tool_nping_strings {
    meta:
        id = "fcfd9539-b224-45b4-9252-0b4d56a40be4"
        version = "1.0"
        description = "Detects NPing"
        author = "Sekoia.io"
        creation_date = "2022-08-11"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "http://nmap.org/nping"
        $ = "nping scanme.nmap.org"
        $ = "Bogus target structure passed to %s"
        $ = "Packet too short."
        $ = "read_arp_reply_pcap"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        3 of them and filesize < 1MB
}
        
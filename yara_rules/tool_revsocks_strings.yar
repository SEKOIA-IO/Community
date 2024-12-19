rule tool_revsocks_strings {
    meta:
        id = "f5f34e74-0795-4c81-a385-218a8197a0b7"
        version = "1.0"
        description = "Detects revsocks client"
        author = "Sekoia.io"
        creation_date = "2024-03-07"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "reverse socks5 server/client by kost" ascii fullword
        $ = "github.com/kost/"
        $ = "revsocks -listen"
        $ = "Start on the DNS server: revsocks -dns"
        $ = "crypto/aes."
        
    condition:
        ( uint32be(0) == 0x7f454c46 or 
          uint16be(0) == 0x4d5a or 
          uint32be(0) == 0xfeedface or 
          uint32be(0) == 0xfeedfacf or 
          uint32be(0) ==  0xcafebabe or
          uint32be(0) ==  0xCFFAEDFE) and
        3 of them
}
        
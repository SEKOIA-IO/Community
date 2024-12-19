rule tool_chisel_strings {
    meta:
        id = "667a8aa3-772b-45f1-8c89-acb7b976888d"
        version = "1.0"
        description = "Detects Chisel"
        author = "Sekoia.io"
        creation_date = "2024-03-14"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "tunnel.(*Tunnel).handleSSHChannel."
        $ = "server.(*Server).handleWebsocket"
        $ = "tunnel.(*udpHandler)"
        $ = "server.(*Server).tlsLetsEncrypt"
        $ = "cnet.(*wsConn).SetPingHandler.(*Conn)"
        $ = "tunnel.(*udpConns).dial."
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 15MB and 3 of them
}
        
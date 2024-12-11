rule sekoiaio_tool_gost_tunnel_strings {
    meta:
        id = "2de7aae9-9cf8-4007-aa27-5caea4123713"
        version = "1.0"
        description = "Detects GOST Go Tunnel, based on strings"
        source = "Sekoia.io"
        creation_date = "2023-02-28"
        classification = "TLP:CLEAR"
        
    strings:
        $ = ".(*shadowUDPHandler).transportUDP" ascii
        $ = ".(*quicCipherConn).decrypt" ascii
        $ = ".(*socks4aConnector).ConnectContext.func1" ascii
        $ = ".(*mtlsTransporter).Handshake" ascii
        $ = ".(*FIFOStrategy).Apply" ascii
        $ = ".dnsTCPExchanger" ascii
        $ = ".dohResponseWriter" ascii
        $ = ".tcpRemoteForwardListener" ascii
        $ = ".shadowUDPPacketConn" ascii
        $ = ".sshTunnelListener" ascii
        $ = "/listener/rtcp/listener.go" ascii
        $ = "/handler/unix/handler.go" ascii
        $ = "/handler/tunnel/tunnel.go"ascii
        $ = "/internal/net/proxyproto/listener.go" ascii
        $ = "/internal/util/serial/conn.go" ascii
        $ = "github.com/go-gost/x" ascii
        
    condition:
        (uint32be(0) == 0x7f454c46 or 
         uint16be(0) == 0x4d5a or 
         uint32be(0) == 0xcefaedfe or 
         uint32be(0) == 0xcffaedfe or 
         uint32be(0) == 0xbebafeca) and
        5 of them
}
        
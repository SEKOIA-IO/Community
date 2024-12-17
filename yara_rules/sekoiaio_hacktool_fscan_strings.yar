rule sekoiaio_hacktool_fscan_strings {
    meta:
        id = "6bef80c3-370c-4168-9d88-3fac88f986b1"
        version = "1.0"
        description = "Detects fscan based on strings"
        author = "Sekoia.io"
        creation_date = "2023-12-06"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Plugins.RdpScan.func1"
        $ = "Plugins.smb1AnonymousConnectIPC.func1"
        $ = "WebScan/WebScan.go"
        $ = "Plugins/CVE-2020-0796.go"
        $ = "Plugins.SshConn.func4"
        $ = "Plugins.PostgresScan"
        $ = "Plugins.(*FCGIClient).Request.func1"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 30MB and
        4 of them
}
        
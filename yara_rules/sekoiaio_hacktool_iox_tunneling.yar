rule sekoiaio_hacktool_iox_tunneling {
    meta:
        id = "45b31d67-95e9-405d-88ea-3f2006ef160a"
        version = "1.0"
        description = "Detects IOX tunneling tool"
        author = "Sekoia.io"
        creation_date = "2022-10-13"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "iox/operate.Local2Remote"
        $ = "iox/operate.Local2Local"
        $ = "iox/operate.Remote2Remote"
        $ = "iox/operate.ProxyLocal"
        $ = "iox/operate.ProxyRemote"
        $ = "iox/operate.ProxyRemoteL2L"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 5MB and
        all of them
}
        
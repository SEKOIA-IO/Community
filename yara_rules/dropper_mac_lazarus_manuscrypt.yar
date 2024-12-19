rule dropper_mac_lazarus_manuscrypt {
    meta:
        id = "6138bd0c-1fcf-4586-b2b6-29955c7d6266"
        version = "1.0"
        description = "MacOS Manuscrypt dropped by TraderTraitor"
        author = "Sekoia.io"
        creation_date = "2022-04-19"
        classification = "TLP:CLEAR"
        hash = "dced1acbbe11db2b9e7ae44a617f3c12d6613a8188f6a1ece0451e4cd4205156"
        hash = "9d9dda39af17a37d92b429b68f4a8fc0a76e93ff1bd03f06258c51b73eb40efa"
        
    strings:
        $ = "networksetup -getwebproxy '%s'" ascii
        $ = "Cookie: _ga=%s%02d%d%d%02d%s" ascii
        $ = "networksetup -listallnetworkservices" ascii
        $ = "gid=%s%02d%d%03d%s" ascii
        
    condition:
        uint32(0) == 0xFEEDFACF
        and all of them
}
        
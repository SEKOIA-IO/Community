rule hacktool_mimikat_ssp_strings {
    meta:
        id = "33b3620f-e02d-4d29-adcc-fea3b49ab780"
        version = "1.0"
        description = "Detects mimikat_ssp"
        author = "Sekoia.io"
        creation_date = "2023-11-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[*] Building RPC packet" ascii
        $ = "[*] Connecting to lsasspirpc RPC service" ascii
        $ = "[*] Sending SspirConnectRpc call" ascii
        $ = "[*] Sending SspirCallRpc call" ascii
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 500KB and
        all of them
}
        
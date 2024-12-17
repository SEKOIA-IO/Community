rule sekoiaio_hacktool_ligolo_strings {
    meta:
        id = "5013256b-eda3-417e-ac72-959055b01c7e"
        version = "1.0"
        description = "Detects ligolo based on strings"
        author = "Sekoia.io"
        creation_date = "2022-02-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Restarting Ligolo..."
        $ = "Ligolo starts a socks5 proxy server"
        $ = "main.startSocksProxy"
        $ = "main.handleRelay"
        $ = "main.StartLigolo"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize > 2MB and filesize < 5MB and
        3 of them
}
        
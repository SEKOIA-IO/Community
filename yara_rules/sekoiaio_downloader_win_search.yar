rule sekoiaio_downloader_win_search {
    meta:
        id = "8094ddda-6294-4dee-93cb-de79aaed1ec6"
        version = "1.0"
        description = "'Search.exe' script used by APT42"
        source = "Sekoia.io"
        creation_date = "2024-08-23"
        classification = "TLP:CLEAR"
        hash = "a29fa85ecfc0e5554c21f3b9db185de97b3504517403f4aa102adbd2c46dc1bf"
        hash = "f83e2b3be2e6db20806a4b9b216edc7508fa81ce60bf59436d53d3ae435b6060"
        
    strings:
        $ = "C:\\Users\\pc\\source\\repos\\Search\\Search\\obj\\Debug\\Search.pdb"
        
    condition:
        uint16be(0) == 0x4d5a and
        all of them
}
        
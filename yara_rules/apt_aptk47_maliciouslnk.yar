rule apt_aptk47_maliciouslnk {
    meta:
        id = "2ccc8777-26fe-4018-9646-4ea91394fe78"
        version = "1.0"
        description = "Detects APT-K-47 malicious LNK"
        author = "Sekoia.io"
        creation_date = "2024-11-22"
        classification = "TLP:CLEAR"
        hash = "6a405d4e88b4acb9706e19a83aad9cf6"
        
    strings:
        $ = "[/c for /f" wide
        $ = "2^>nul') do copy" wide
        $ = "%F in ('where /r %Temp%" wide
        
    condition:
        uint32be(0) == 0x4c000000 and all of them
}
        
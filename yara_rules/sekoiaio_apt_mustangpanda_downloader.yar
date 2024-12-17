rule sekoiaio_apt_mustangpanda_downloader {
    meta:
        id = "54850ffd-f93b-4082-b3ca-8e1d60b35422"
        version = "1.0"
        description = "Detects the MustangPanda Downloader"
        author = "Sekoia.io"
        creation_date = "2022-03-02"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Windows Api" wide nocase
        $ = "200 OK" wide
        $ = "200 ok" wide
        $ = "mscoree.dll" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        all of them
}
        
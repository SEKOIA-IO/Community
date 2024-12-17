rule sekoiaio_apt_aptk47_asyncshell {
    meta:
        id = "2d009cf4-e30e-406d-8860-03b37a396ffa"
        version = "1.0"
        description = "Detects APT-K-47's Asyncshell"
        author = "Sekoia.io"
        creation_date = "2024-11-22"
        classification = "TLP:CLEAR"
        hash = "ce6a589d5e3604112e5595a1f8d53e1e"
        hash = "751f427da8e11d8ab394574260735220"
        
    strings:
        $ = "Error executing command:" wide
        $ = "Error occurred:" wide
        $ = "Attempting to reconnect in {0} seconds..." wide
        $ = "Exiting the application." wide
        $ = "Server disconnected." wide
        $ = "_CorExeMain"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and 
        4 of them
}
        
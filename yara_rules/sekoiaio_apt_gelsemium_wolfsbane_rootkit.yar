rule sekoiaio_apt_gelsemium_wolfsbane_rootkit {
    meta:
        id = "e93f4515-62f5-4057-a464-aae11cbe0639"
        version = "1.0"
        description = "Detects Gelsemium's WolfsBane rootkit"
        author = "Sekoia.io"
        creation_date = "2024-11-22"
        classification = "TLP:CLEAR"
        hash = "ba08e63ad65a9bdcdb1655f25d32c808"
        
    strings:
        $ = "__non_hooked_symbols"
        $ = "__hidden_literals"
        $ = "extract_type_2_socket_inode2"
        $ = "/proc/%s/fd"
        $ = "pluginkey" wide
        $ = "mainpath" wide
        $ = "hiderpath" wide
        
    condition:
        uint32be(0) == 0x7f454c46 and 
        filesize < 1MB and
        all of them
}
        
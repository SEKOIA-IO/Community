rule sekoiaio_apt_gelsemium_wolfsbane_backdoor {
    meta:
        id = "db2ad5a4-b592-4646-a385-c668bb2ea090"
        version = "1.0"
        description = "Detects Gelsemium's WolfsBane backdoor"
        author = "Sekoia.io"
        creation_date = "2024-11-22"
        classification = "TLP:CLEAR"
        hash = "1418fe9a743226b9661a2b6decb19db0"
        
    strings:
        $ = "udp_session"
        $ = "session_interface"
        $ = "plugin_persist"
        $ = "Udp.cpp"
        $ = "ikcp.c"
        $ = "' %s 2>/dev/null"
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize > 3MB and
        filesize < 4MB and
        4 of them
}
        
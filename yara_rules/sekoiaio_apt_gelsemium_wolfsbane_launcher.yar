rule sekoiaio_apt_gelsemium_wolfsbane_launcher {
    meta:
        id = "26fbf4df-aa08-47b6-a73c-e8f80a408454"
        version = "1.0"
        description = "Detects Gelsemium's WolfsBane launcher"
        source = "Sekoia.io"
        creation_date = "2024-11-22"
        classification = "TLP:CLEAR"
        hash = "87e437cf74ce4b1330b8af9ff71edae2"
        
    strings:
        $ = "rm -f /dev/shm/sem*%s"
        $ = "/etc/ld.so.preload"
        $ = "kill -9 %d 2>/dev/null"
        $ = "/,1d' %s 2>/dev/null"
        
    condition:
        uint32be(0) == 0x7F454C46 and 
        filesize < 500KB and 
        all of them
}
        
rule sekoiaio_apt_coathanger_files {
    meta:
        id = "615f5ac1-14bc-4f5b-a02e-7b13cd179917"
        version = "1.0"
        description = "Detects COATHANGER files"
        author = "Sekoia.io"
        creation_date = "2024-02-07"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "/data2/"
        $ = "/httpsd"
        $ = "/preload.so"
        $ = "/authd"
        $ = "/tmp/packfile"
        $ = "/smartctl"
        $ = "/etc/ld.so.preload"
        $ = "/newcli"
        $ = "/bin/busybox"
        
    condition:
        (uint32(0) == 0x464c457f or uint32(4) == 0x464c457f)
        and filesize < 5MB and 4 of them
}
        
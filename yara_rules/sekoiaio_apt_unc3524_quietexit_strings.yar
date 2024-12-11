rule sekoiaio_apt_unc3524_quietexit_strings {
    meta:
        id = "1bfa9baa-40a3-4ad7-83dc-f9340fbed180"
        version = "1.0"
        description = "Detect the QUIETEXIT malware used by UNC3524"
        source = "Sekoia.io"
        creation_date = "2022-05-04"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Child connection from %s:%s" ascii
        $ = "Failed to run %s" ascii
        $ = "add %s %s %s" ascii
        $ = "/usr/bin/xauth -q" ascii
        $ = "/tmp/dropbear-%" ascii
        $ = "cron" ascii
        $ = { DD E5 D5 97 20 53 27 BF F0 A2 BA CD 96 35 9A AD 1C 75 EB 47 }
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize > 1MB and
        5 of them
}
        
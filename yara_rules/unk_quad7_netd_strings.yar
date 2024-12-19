rule unk_quad7_netd_strings {
    meta:
        id = "3f527f0e-c101-4356-9024-fc61aea644d1"
        version = "1.0"
        description = "Matches netd binary"
        author = "Sekoia.io"
        creation_date = "2024-08-23"
        classification = "TLP:CLEAR"
        hash = "cdb37db4543dde5ca2bd98a43699828f"
        
    strings:
        $ = "./netd.dat"
        $ = "./sys.dat"
        $ = "--conf"
        $ = "--init"
        $ = "--nobg"
        $ = "Url is NULL."
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 1MB and
        4 of them
}
        
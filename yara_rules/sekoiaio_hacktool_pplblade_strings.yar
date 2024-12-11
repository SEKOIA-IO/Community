rule sekoiaio_hacktool_pplblade_strings {
    meta:
        id = "1a443621-fc95-4a70-873e-c1389943d4ab"
        version = "1.0"
        description = "Detects PPLBlade"
        source = "Sekoia.io"
        creation_date = "2023-11-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "shirou/gopsutil/internal/"
        $ = ".miniDumpWriteDump"
        $ = ".DRIVER_FULL_PATH"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize > 4MB and filesize < 6MB and
        all of them
}
        
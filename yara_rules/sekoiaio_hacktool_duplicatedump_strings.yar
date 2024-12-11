rule sekoiaio_hacktool_duplicatedump_strings {
    meta:
        id = "081d0124-4afe-418b-9767-3d987c0107ca"
        version = "1.0"
        description = "Detects Duplicate Dump"
        source = "Sekoia.io"
        creation_date = "2023-11-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "7d872e921a4b4b1b8b295395099b0209" wide ascii
        $ = "[+] Named pipe connected and replying with current PID" wide ascii
        $ = "[X] Named pipe connection error:" wide ascii
        $ = "[X] Error occur while compressing file:" wide ascii
        $ = "[+] Dump file saved to" wide ascii
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 500KB and
        4 of them
}
        
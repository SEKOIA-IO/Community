rule sekoiaio_tool_quarkspwdump {
    meta:
        id = "859823f9-6d47-4b0f-844b-d3af7bad498b"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-06-23"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "quarks-pwdump.exe"
        $s2 = "--------------------------------------------- BEGIN DUMP --------------------------------------------"
        $s3 = "%s_hist%d:\"\":\"\":%s:%s"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 1MB and
        all of them
}
        
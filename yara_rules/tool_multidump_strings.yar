rule tool_multidump_strings {
    meta:
        id = "4897c898-01dd-40d2-bf28-266231c88f8a"
        version = "1.0"
        description = "Detects MultiDump"
        author = "Sekoia.io"
        creation_date = "2024-03-19"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "--nodump\tDisable LSASS dumping"
        $ = "-r 192.168.1.100:5000"
        $ = "Path to save procdump.exe"
        $ = "[!] CreateFileW [R] Failed With Error"
        $ = "LSASS is Running, Continuin"
        $ = "Dumping LSASS Using ProcDump"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        3 of them
}
        
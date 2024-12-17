rule sekoiaio_rat_win_reverserat {
    meta:
        id = "8fbd395f-f44e-46d5-a942-7c7e88f37127"
        version = "1.0"
        description = "Detect SideCopy's ReverseRAT v3 observed in January 2023"
        author = "Sekoia.io"
        creation_date = "2023-02-22"
        classification = "TLP:CLEAR"
        hash = "b277a824b2671f40298ce03586a2ccc0fca2a081a66230c57a3060c2028f13ee"
        hash = "8b87459483248d7b95424cd52b7d4f3031e89c6644adc2e167556e071d9ec3aa"
        
    strings:
        $ = "SELECT maxclockspeed,  datawidth, name, manufacturer FROM Win32_Processor" wide
        $ = "select * from Win32_PhysicalMemory" wide
        $ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
        
    condition:
        all of them
}
        
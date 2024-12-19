rule apt_kimsuky_fpspy {
    meta:
        id = "75d41851-a7a6-4068-8ea5-6a3e6e62a965"
        version = "1.0"
        description = "Detects FPSpy, a backdoor used by Kimsuky"
        author = "Sekoia.io"
        creation_date = "2024-09-27"
        classification = "TLP:CLEAR"
        hash = "6d6c1b175e435f5564341cc1f2c33ddf"
        hash = "54c58b72f98cb63c44e7694add551e9d"
        
    strings:
        $ = "Chrome/31.0." wide
        $ = "%srundll32.exe %s, %s %%1" wide
        $ = "MazeFunc" wide
        $ = "sys.dll" wide
        $ = "KLog" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        4 of them
}
        
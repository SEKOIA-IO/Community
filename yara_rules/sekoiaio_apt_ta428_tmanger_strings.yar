rule sekoiaio_apt_ta428_tmanger_strings {
    meta:
        id = "f600404d-3f93-4e3f-bba7-9f519f67c6cb"
        version = "1.0"
        description = "Detects Tmanger malware"
        author = "Sekoia.io"
        creation_date = "2022-09-06"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "sock_hmutex" wide ascii
        $ = "cmd_hmutex" wide ascii
        $ = "%s_%d.bmp" wide ascii
        $ = "WSAStartup Error!" wide ascii
        $ = "4551-8f84-08e738aec" wide ascii
        $ = "Init failed!" wide ascii
        $ = "GetLanIP error!" wide ascii
        $ = "chcp & exit" wide ascii
        $ = "GetHostname error!" wide ascii
        $ = "[Num Lock]" wide ascii
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 200KB and
        4 of them
}
        
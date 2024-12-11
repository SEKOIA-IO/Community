rule sekoiaio_apt_oilrig_saitama_backdoor_may2022 {
    meta:
        id = "4ea8c27f-c441-4616-a29b-2b5dfdd3bd20"
        version = "1.0"
        description = "Detects tje Saitama backdoor"
        source = "Sekoia.io"
        creation_date = "2022-05-13"
        classification = "TLP:CLEAR"
        
    strings:
        $ = { 7E [4] 7E [4] 59 0A 02 8E 69 06 28 [4] D1 0B 02 16 7E [4] 7E [4] 07 }
        $ = "systeminfo | findstr" wide
        $ = "powershell -exec bypass -enc" wide
        $ = "SendAndReceive : {0}" wide
        $ = "SleepSecond : Start" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        2 of them
}
        
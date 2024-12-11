rule sekoiaio_backdoor_powershellempire_sharpire {
    meta:
        id = "fed21fbd-52ed-4649-a1ff-56eae57fc9ef"
        version = "1.0"
        description = "Detect Sharpire version of Empire"
        source = "Sekoia.io"
        creation_date = "2022-04-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "GetAgentID" ascii wide
        $ = "SetAgentID" ascii wide
        $ = "StartAgentJob" ascii wide
        $ = "get_JobThread" ascii wide
        $ = "GetStagerURI" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and 4 of them  and filesize < 1MB
}
        
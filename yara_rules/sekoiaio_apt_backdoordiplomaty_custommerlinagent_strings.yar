rule sekoiaio_apt_backdoordiplomaty_custommerlinagent_strings {
    meta:
        id = "965693ba-93b8-4c52-9292-957884411968"
        version = "1.0"
        description = "Detects custom variant of Merlin agent used by BackdoorDiplomaty"
        author = "Sekoia.io"
        creation_date = "2024-06-06"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "agent.GetSpecificID"
        $ = "agent.ExecuteCommand"
        $ = "agent.getClient"
        $ = "agent.SignalListen"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 10MB and
        all of them
}
        
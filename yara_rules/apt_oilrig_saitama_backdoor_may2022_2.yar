rule apt_oilrig_saitama_backdoor_may2022_2 {
    meta:
        id = "f885551a-d0f0-431d-aa4f-7caa93b1db6a"
        version = "1.0"
        description = "Detects Saitama backdoor variants"
        author = "Sekoia.io"
        creation_date = "2022-05-13"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "_CorExeMain"
        $ = "GetAgentID"
        $ = "ComputeStringHash"
        $ = ".Agent.pdb"
        $ = "TaskExecTimeout"
        
    condition:
        uint16be(0) == 0x4d5a and
        5 of them
}
        
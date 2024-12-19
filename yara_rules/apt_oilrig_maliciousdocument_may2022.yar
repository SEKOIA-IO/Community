rule apt_oilrig_maliciousdocument_may2022 {
    meta:
        id = "cb4ab310-e24c-4edc-8804-0c49c30124fb"
        version = "1.0"
        description = "Detects OilRig Malicious Document"
        author = "Sekoia.io"
        creation_date = "2022-05-13"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "<LogonType>InteractiveToken</LogonType>"
        $s2 = "Select * From Win32_PingStatus Where Address"
        $s3 = "She@et1"
        $s4 = "_VBA_PROJECT" wide
        $s5 = "This program cannot be run in DOS mode." base64
        $s6 = ".Agent.pdb" base64
        $s7 = "GetAgentID" base64
        
    condition:
        uint32be(0) == 0xD0CF11E0 and
        3 of them
}
        
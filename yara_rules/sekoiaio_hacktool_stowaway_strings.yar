rule sekoiaio_hacktool_stowaway_strings {
    meta:
        id = "a952b45a-269b-4075-bf72-16d6d863e97c"
        version = "1.0"
        description = "Detects Stowaway based on strings"
        author = "Sekoia.io"
        creation_date = "2023-11-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "agent.CloseLowConn"
        $ = "agent.CloseListener"
        $ = "agent.SimpleNodeInit"
        $ = "agent.HandleConnToLowerNode"
        $ = "agent.HandleConnFromLowerNode"
        $ = "common.NewPassToLowerNodeData"
        $ = "agent.HandleSimpleNodeConn"
        $ = "agent.HandleConnToUpperNode"
        $ = "agent.HandleConnFromUpperNode"
        $ = "agent.StartSocks"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and all of them
}
        
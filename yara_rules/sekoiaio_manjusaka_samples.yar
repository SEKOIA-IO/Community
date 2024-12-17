rule sekoiaio_manjusaka_samples {
    meta:
        id = "7aa8edb3-2e67-4632-af68-5b65c9aefe39"
        version = "1.0"
        author = "Sekoia.io"
        description = "Detects Manjusaka via protobuf struture names (Windows / Linux / implants / C2)"
        creation_date = "2022-08-04"
        classification = "TLP:CLEAR"
        
    strings:
        $ = ".protos.AgentStatusR" ascii wide
        $ = ".protos.AgentsR" ascii wide
        $ = ".protos.FileActionR" ascii wide
        $ = ".protos.FileEntryR" ascii wide
        $ = ".protos.HttpFileActionR" ascii wide
        $ = ".protos.HttpFileEntryR" ascii wide
        $ = ".protos.PassResultR" ascii wide
        $ = ".protos.PortResultR" ascii wide
        $ = ".protos.PortResultR" ascii wide
        $ = ".protos.PortResultR" ascii wide
        $ = ".protos.ConfigH" ascii wide
        $ = ".protos.AgentUpdateH" ascii wide
        $ = ".protos.PluginExecH" ascii wide
        $ = ".protos.PluginLoadH" ascii wide
        $ = ".protos.ReqCwdH" ascii wide
        $ = ".protos.ReqCmdH" ascii wide
        $ = ".protos.ReqListFileH" ascii wide
        $ = ".protos.ReqCatFileH" ascii wide
        $ = ".protos.ReqNetStatH" ascii wide
        $ = ".protos.ReqTaskListH" ascii wide
        $ = ".protos.ReqScreenH" ascii wide
        $ = ".protos.FileEventH" ascii wide
        $ = ".protos.HttpFileEventH" ascii wide
        $ = ".protos.PassGetEventH" ascii wide
        $ = ".protos.FileGetEventH" ascii wide
        $ = ".protos.AgentEventR" ascii wide
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        15 of them
}
        
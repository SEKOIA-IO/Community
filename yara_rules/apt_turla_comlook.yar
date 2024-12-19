rule apt_turla_comlook {
    meta:
        id = "c3bf886b-f952-47f9-aff6-3cd74c27077d"
        version = "1.0"
        description = "Detects Class and Method names used inside ComLook"
        author = "Sekoia.io"
        creation_date = "2023-10-30"
        classification = "TLP:CLEAR"
        
    strings:
        $ClassName1 = "AgentConfig"
        $ClassName2 = "CommandPerforming"
        
        
        $MethodName1 = "CmdCommand"
        $MethodName2 = "GetConfigCommand"
        $MethodName3 = "GetFileCommand"
        $MethodName4 = "PutFileCommand"
        $MethodName5 = "SetConfigCommand"
        $MethodName6 = "AgentProtocol"
        
        $Log1 = "CONFIG_SERVERS_LIST_PARSING_ERROR" ascii wide
        $Log2 = "GET_UIDS_TO_CHECK_PARSING_ERROR" ascii wide
        $Log3 = "PAYLOAD_PARSING_FILEPATH_AND_FILE_ERROR" ascii wide
        $Log4 = "COMMAND_EMPTY_ERROR" ascii wide
        $Log5 = "IMAP_USERNAME_FORMAT_INCORRECT" ascii wide
        $Log6 = "NO_MESSAGES_TO_RETRIEVE" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 10MB and any of ($ClassName*) and any of ($MethodName*) and any of ($Log*)
}
        
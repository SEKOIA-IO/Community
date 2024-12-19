rule apt_apt33_falsefont {
    meta:
        id = "d77c1f5b-9898-456f-954a-ac1f0907a2ba"
        version = "1.0"
        description = "FalseFont backdoor"
        author = "Sekoia.io"
        creation_date = "2024-03-25"
        classification = "TLP:CLEAR"
        
    strings:
        $s0 = "Agent.Core.WPF"
        $s1 = "data2.txt" wide fullword
        $s2 = "data.txt" wide fullword
        $s3 = "Loginvault.db" wide fullword
        $command1 = "ExecUseShell" ascii
        $command2 = "ExecAndKeepAlive" ascii
        $command3 = "CMD" ascii
        $command4 = "PowerShell" ascii
        $command5 = "KillByName" ascii
        $command6 = "KillById" ascii
        $command7 = "Download" ascii
        $command8 = "Upload" ascii
        $command9 = "Delete" ascii
        $command10 = "GetDirectories" ascii
        $command11 = "ChangeTime" ascii
        $command12 = "SendAllDirectory" ascii
        $command13 = "UpadateApplication" ascii
        $command14 = "Restart" ascii
        $command15 = "GetProcess" ascii
        $command16 = "SendAllDirectoryWithStartPath" ascii
        $command17 = "GetDir" ascii
        $command18 = "GetHard" ascii
        $command19 = "GetScreen" ascii
        $command20 = "StopSendScreen" ascii
        
    condition:
        uint16be(0) == 0x4d5a and 15 of ($command*) and 3 of ($s*)
}
        
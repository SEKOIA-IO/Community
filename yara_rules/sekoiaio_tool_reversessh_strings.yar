rule sekoiaio_tool_reversessh_strings {
    meta:
        id = "b20c2c8e-3910-4545-a87a-3d428283a447"
        version = "1.0"
        description = "Detects reverse SSH based on strings"
        author = "Sekoia.io"
        creation_date = "2024-04-16"
        classification = "TLP:CLEAR"
        
    strings:
        $fun_1 = "createLocalPortForwardingCallback"
        $fun_2 = "createReversePortForwardingCallback"
        $fun_3 = "createPasswordHandler"
        $fun_4 = "createPublicKeyHandler"
        $fun_5 = "createSFTPHandler"
        $fun_6 = "dialHomeAndListen"
        $fun_7 = "createExtraInfoHandler"
        $fun_8 = "createSSHSessionHandler"
        $fun_9 = "createReversePortForwardingCallback"
        $proj_1 = "github.com/Fahrj/reverse-ssh"
        
    condition:
        any of ($proj_*) or
        4 of ($fun_*)
}
        
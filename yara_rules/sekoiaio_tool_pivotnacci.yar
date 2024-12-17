rule sekoiaio_tool_pivotnacci {
    meta:
        id = "31ecb08a-fc92-4cbe-a865-7ce869a5fa6a"
        version = "1.0"
        description = "Detects Pivotnacci"
        author = "Sekoia.io"
        creation_date = "2024-04-22"
        classification = "TLP:CLEAR"
        
    strings:
        $pivotnacci = "pivotnacci"
        $s1 = "Socks server => %s:%s"
        $s2 = "The default listening address"
        $s3 = "Socks server for HTTP agents"
        $s4 = "Message returned by the agent web page"
        $s5 = "Password to communicate with the agent"
        $s6 = "To specify agent type in case is not automatically detected."
        
    condition:
        $pivotnacci and 3 of ($s*)
}
        
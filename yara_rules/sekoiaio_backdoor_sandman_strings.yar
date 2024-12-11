rule sekoiaio_backdoor_sandman_strings {
    meta:
        id = "7bac7a1e-7d4a-4410-9ad4-1c85beb6faaf"
        version = "1.0"
        description = "Detect the Sandman backdoor based on strings"
        source = "Sekoia.io"
        creation_date = "2022-08-23"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "e9f7c24c-879d-49f2-b9bf-2477dc28e2ee"
        $s2 = "System.Net.Sockets"
        $s3 = "ntpServer"
        $s4 = "payloadUrl"
        $s5 = "keepRunning"
        $s6 = "payloadSize"
        $s7 = "defaultNtpMessageSize"
        $s8 = "InjectShellcode"
        
    condition:
        uint16be(0) == 0x4d5a and
        7 of them or $s1
}
        
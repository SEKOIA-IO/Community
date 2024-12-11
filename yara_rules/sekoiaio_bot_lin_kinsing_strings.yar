rule sekoiaio_bot_lin_kinsing_strings {
    meta:
        id = "ce41b6d0-bc22-4a85-a3bb-ed3234871524"
        version = "1.0"
        description = "Catch Kinsing malware based on strings"
        source = "Sekoia.io"
        creation_date = "2023-11-24"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "MinerUrl" ascii
        $s2 = "main.masscan" ascii
        $s3 = "redisBrute" ascii
        $s4 = "ActiveC2CUrl" ascii
        $s5 = "main.getKi" ascii
        $s6 = "main.getMu" ascii
        $s7 = "tryToRunMiner" ascii
        $s8 = "main.kiLoader" ascii
        $s9 = "main.downloadAndExecute" ascii
        
    condition:
        uint32(0)==0x464c457f and all of them
}
        
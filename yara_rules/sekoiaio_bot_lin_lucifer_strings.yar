rule sekoiaio_bot_lin_lucifer_strings {
    meta:
        id = "c341b6d0-bc22-4a85-aebb-ed323487f524"
        version = "1.0"
        description = "Catch Lucifer DDoS - lin version - malware based on strings"
        source = "Sekoia.io"
        creation_date = "2024-09-24"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "DealwithDDoS" ascii
        $s2 = "DecryptData" ascii
        $s3 = "They say I'm rude. I'm not rude at all, but I still want to say, fuck your mother" ascii
        $s4 = "stratum+tcp://" ascii
        $s5 = "gethostip" ascii
        $s6 = "GetmyName" ascii
        
    condition:
        uint32(0)==0x464c457f and all of them
}
        
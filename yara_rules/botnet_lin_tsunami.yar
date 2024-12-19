rule botnet_lin_tsunami {
    meta:
        id = "65d2ff89-064f-489a-a215-33197926a62d"
        version = "1.0"
        description = "Catch tsunami botnet based on string"
        author = "Sekoia.io"
        creation_date = "2024-09-24"
        classification = "TLP:CLEAR"
        hash = "536a28db011459d841652e25a852ccf2"
        
    strings:
        $n = "NOTICE %s" ascii
        $t = "TSUNAMI" ascii nocase
        $s1 = "NICK" ascii fullword
        $s2 = "GETSPOOFS" ascii fullword
        $s3 = "IRC" ascii fullword
        $s4 = "PONG" ascii
        
    condition:
        uint32(0)==0x464c457f and #n > 40 and #t > 3 and 3 of ($s*)
}
        
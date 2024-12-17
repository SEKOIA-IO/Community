rule sekoiaio_generic_tor_hidden_service_leading_to_winports {
    meta:
        id = "1e5c469b-f721-44af-87b3-1adf423719c1"
        version = "1.0"
        description = "Detects malicious TOR redirection affecting RDP, NetBios"
        author = "Sekoia.io"
        creation_date = "2023-09-07"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "HiddenServiceDir "
        $s2 = "SocksPort "
        $s3 = "HiddenServicePort "
        $s4 = ":3389"
        $s5 = ":445"
        
    condition:
        $s1 and $s2 
        and ($s4 in (@s3..@s3+100) or $s5 in (@s3..@s3+100))
        and filesize < 2000
}
        
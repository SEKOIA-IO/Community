rule sekoiaio_water_sigbin_group {
    meta:
        id = "c49728e8-db7e-4d83-97d2-7d56b51f8a52"
        version = "1.0"
        description = "Detects IOCs related to the 8220 Mining group."
        author = "Sekoia.io"
        creation_date = "2024-06-11"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "Z12A3" ascii fullword
        $s2 = "FromBase64String" ascii fullword
        $s3 = "Start-Process" ascii fullword
        $s4 = "WriteAllBytes" ascii fullword
        
    condition:
        all of them
}
        
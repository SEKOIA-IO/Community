rule sekoiaio_spyware_and_strongpity_mobile_backdoor {
    meta:
        id = "58ceb85b-d94f-47b2-86e4-59bd41f4fea8"
        version = "1.0"
        description = "Detect the mobile backdoor using the name used in the certificate"
        author = "Sekoia.io"
        creation_date = "2023-01-16"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "Elizabeth Mckinsen0"
        
    condition:
        all of them and filesize > 2MB
}
        
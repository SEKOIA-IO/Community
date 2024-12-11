rule sekoiaio_apt_micdown_encrypted_configuration {
    meta:
        id = "9567d68b-05d1-4d41-b87f-c8691ee689cd"
        version = "1.0"
        description = "Encrypted C2 configuration of micDown"
        source = "Sekoia.io"
        creation_date = "2023-08-24"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = {?? [20] 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 84 36}
        
    condition:
        filesize == 66 and all of them
}
        
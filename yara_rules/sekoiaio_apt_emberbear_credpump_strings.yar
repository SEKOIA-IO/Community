rule sekoiaio_apt_emberbear_credpump_strings {
    meta:
        id = "c9898e34-4ab8-49d6-9c8a-3fce592449e2"
        version = "1.0"
        description = "Detects CredPump backdoor"
        author = "Sekoia.io"
        creation_date = "2023-02-28"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "User=%s Pass=%s Host=%s"
        $ = "/etc/rc0.d/.rc0.d"
        $ = "pam_get_authtok"
        $ = "Password:"
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 200KB and
        all of them
}
        
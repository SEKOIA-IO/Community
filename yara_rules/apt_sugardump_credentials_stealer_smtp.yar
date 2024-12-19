rule apt_sugardump_credentials_stealer_smtp {
    meta:
        id = "bf028ebc-bfaa-45b3-9a3f-8949a5efbb73"
        version = "1.0"
        description = "Detects SUGARDUMP SMTP version"
        author = "Sekoia.io"
        creation_date = "2022-08-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "<<<<<<<< ------ Passwords Total: {0} --------- >>>>>>>>" wide
        $ = "Url = {0} , Count = {1}" wide
        $ = "smtp." wide
        $ = "encrypted_key\":\"(.*?)\"" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        all of them
}
        
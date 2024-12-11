rule sekoiaio_apt_badmagic_generic_pshscript {
    meta:
        id = "82cda554-3c2b-4c04-b9f9-b5ba50c53271"
        version = "1.0"
        description = "Detects BadMagic generic powershell script (Possible FPs)"
        source = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$ExecutablePath"
        $ = "Start-Sleep -Second 2"
        
    condition:
        all of them and filesize < 1KB
}
        
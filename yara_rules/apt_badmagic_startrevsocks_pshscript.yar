rule apt_badmagic_startrevsocks_pshscript {
    meta:
        id = "a6c96aee-9e78-47d2-afe3-f3c5246a9370"
        version = "1.0"
        description = "Detects BadMagic DLL Loader powershell script"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$ExecutablePath"
        $ = "Start-Sleep -Second 2"
        $ = "recn -15 -rect 15"
        
    condition:
        all of them and filesize < 1KB
}
        
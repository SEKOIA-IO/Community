rule sekoiaio_apt_apt41_powershell_collection_script {
    meta:
        id = "55b6cc3e-24b2-4faa-a7fb-b4203a8e6d83"
        version = "1.0"
        description = "Detects PowerShell collection script"
        source = "Sekoia.io"
        creation_date = "2023-11-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$yestoday.ToString(" ascii wide nocase
        $ = "$m.LastAccessTime -" ascii wide nocase
        $ = "$fmat=" ascii wide nocase
        $ = "$computername" ascii wide nocase
        $ = "Rar.exe" ascii wide nocase
        
    condition:
        filesize < 10KB and all of them
}
        
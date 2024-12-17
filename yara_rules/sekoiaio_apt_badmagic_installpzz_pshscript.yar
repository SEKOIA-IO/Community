rule sekoiaio_apt_badmagic_installpzz_pshscript {
    meta:
        id = "d01bc217-9e14-498b-a92a-17f6aedec269"
        version = "1.0"
        description = "Detects BadMagic InstallPZZ powershell script"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "start-job -ScriptBlock $script;"
        $ = "Start-Sleep -Second 1;"
        $ = "Write-Output \"$url$j"
        $ = "Start-Sleep -Second 2;"
        
    condition:
        all of them and filesize < 1KB
}
        
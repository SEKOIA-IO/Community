rule apt_apt41_powershell_exfiltration_script {
    meta:
        id = "9a15f845-c0af-4f1c-a033-b4f40232dc0d"
        version = "1.0"
        description = "Detects PowerShell exfiltration script"
        author = "Sekoia.io"
        creation_date = "2023-11-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$UPLOAD_PASSPORT" ascii wide nocase
        $ = "$fileName=$singleFile.Name" ascii wide nocase
        $ = "Upload-Passport" ascii wide nocase
        $ = "$singleFile in $files" ascii wide nocase
        
    condition:
        filesize < 10KB and all of them
}
        
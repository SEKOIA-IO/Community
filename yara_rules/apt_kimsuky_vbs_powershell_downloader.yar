rule apt_kimsuky_vbs_powershell_downloader {
    meta:
        id = "4c9af11f-802b-4ffe-9783-90fc2ee53809"
        version = "1.0"
        description = "Detects VBS/Powershell Downloader used by Kimsuky"
        author = "Sekoia.io"
        creation_date = "2022-08-30"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "& WScript.ScriptFullName &" ascii fullword
        $ = "/c schtasks /create /sc minute /mo 5 /tn"
        $ = "pOwErsHeLl -ep bypass -encodedCommand"
        
    condition:
        filesize < 200KB and
        2 of them
}
        
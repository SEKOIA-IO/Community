rule sekoiaio_apt_apt28_powershell_ntlm_stealer {
    meta:
        id = "3fb5c472-6b1c-490e-b38f-4d4f1c472f43"
        version = "1.0"
        description = "Detects the NTLM Stealer used by APT28 against UA energy sector"
        author = "Sekoia.io"
        creation_date = "2023-09-07"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "'NTLM ' = [Convert]::ToBase64String"
        $ = ".Prefixes.Add('http://localhost:8080/')"
        $ = ".AddHeader('WWW-Authenticate', 'NTLM')"
        $ = "GetValues('Authorization');"
        $ = "[0] -split '\\s+';"
        
    condition:
        3 of them and filesize < 4000
}
        
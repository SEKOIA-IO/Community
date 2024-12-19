rule apt_badmagic_startngrok_pshscript {
    meta:
        id = "94d64482-3033-4531-8530-58546364ac06"
        version = "1.0"
        description = "Detects BadMagic StartNgrok powershell script"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$ExecutablePath http \"\"file:///$Disk"
        $ = "write \"$ExecutablePath not found"
        $ = "$ng_proxy_string ="
        $ = "$ng_auth_token ="
        $ = "$env:ALLUSERSPROFILE\\$NGrokFolderName"
        
    condition:
        all of them and filesize < 1KB
}
        
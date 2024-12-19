rule loader_win_batloader_scripts {
    meta:
        version = "1.0"
        description = "Finds BatLoader samples based on the specific download URL"
        author = "Sekoia.io"
        creation_date = "2022-11-30"
        id = "31a04ad3-74f8-4aa5-b3fc-df792bdc71b5"
        classification = "TLP:CLEAR"
        
    strings:
        $url = /https?:\/\/[^\s]{15,35}\/index\/[^\s]{1,40}servername=msi/ ascii wide
        
        $str00 = "Invoke-WebRequest" ascii wide
        $str01 = "PSScriptRoot" ascii wide
        $str02 = "Add-MpPreference" ascii wide
        $str03 = "Install-GnuPG" ascii wide
        $str04 = "wmic computersystem get domain" ascii wide
        $str05 = "ArpInfo" ascii wide
        $str06 = "$script:List_ProccesCheck" ascii wide
        $str07 = "Get-Process -Name" ascii wide
        $str08 = "f001_SetProcessList" ascii wide
        $str09 = "var WshShell" ascii wide
        $str10 = "WScript.Sleep" ascii wide
        $str11 = "WshShell.Run" ascii wide
        $str12 = "powershell Invoke-WebRequest" ascii wide
        $str13 = "-nop -w hidden " ascii wide
        
    condition:
        $url and 2 of ($str*) and filesize < 50KB
}
        
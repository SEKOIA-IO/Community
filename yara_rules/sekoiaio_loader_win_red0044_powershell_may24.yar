rule sekoiaio_loader_win_red0044_powershell_may24 {
    meta:
        id = "ba3454b4-31cf-458d-8d78-c5cc5fa348ff"
        version = "1.0"
        description = "Finds PowerShell scripts used in a malvertising campaign to deliver NetSupport RAT"
        source = "Sekoia.io"
        reference = "https://twitter.com/crep1x/status/1786150734121120075"
        creation_date = "2024-05-03"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "Start-Job -ScriptBlock" ascii
        $str02 = "Get-WmiObject" ascii
        $str03 = "-Class Win32_OperatingSystem" ascii
        $str04 = "-Class AntiVirusProduct" ascii
        $str05 = "$_.Exception.Message" ascii
        $str06 = ".DownloadString" ascii
        $str07 = "New-Object Net.WebClient" ascii
        $str08 = "myUserAgentHere" ascii
        $str09 = "GetFolderPath('Desktop'))\\document.pdf" ascii
        $str10 = "Receive-Job -Job" ascii
        $str11 = "Start-Process" ascii
        
    condition:
        8 of them and filesize < 20KB
}
        
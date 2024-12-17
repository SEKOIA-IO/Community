rule sekoiaio_infostealer_win_solarmarker_powershell {
    meta:
        version = "1.0"
        description = "Finds SolarMarker PowerShell script based on characteristic strings"
        author = "Sekoia.io"
        creation_date = "2022-12-09"
        id = "a2fe7f09-7134-4054-ba40-5ea66785a26d"
        classification = "TLP:CLEAR"
        
    strings:
        $fun = "function " ascii
        
        $ps0 = "return -join (0..(10..30|Get-Random)|%{[char]((65..90)+(97..122)|Get-Random)})" ascii
        $ps1 = /new-item -path \$[a-zA-Z0-9_]* -itemtype registrykey -force;/
        $ps2 = /set-item -path \$[a-zA-Z0-9_]* -value \$[a-zA-Z0-9_]*;/
        
        $str0 = "[IO.File]::WriteAllText($" ascii
        $str1 = "CreateShortcut($env:appdata+" ascii
        $str2 = "Registry::HKEY_CURRENT_USER\\Software\\Classes\\" ascii
        $str3 = "New-Object System.Security.Cryptography.AesCryptoServiceProvider" ascii
        $str4 = "[Convert]::FromBase64String([IO.File]::ReadAllText(" ascii
        
    condition:
        $fun at 0 and 1 of ($ps*) and 2 of ($str*)
}
        
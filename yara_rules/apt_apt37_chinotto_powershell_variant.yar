rule apt_apt37_chinotto_powershell_variant {
    meta:
        id = "fa42b225-58fe-4e00-b84b-df37491d8fdd"
        version = "1.0"
        description = "Detects APT37 Chinotto Powershell Variant"
        author = "Sekoia.io"
        creation_date = "2023-03-06"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$env:COMPUTERNAME + '-' + $env:USERNAME;" ascii wide
        $ = "while($true -eq $true)" ascii wide
        $ = "Start-Sleep -Seconds" ascii wide
        $ = " -ne 'null' -and $" ascii wide
        $ = "= 'R=' + [System.Convert]::" ascii wide
        $ = "[string]$([char]0x0D) + [string]$([char]0x0A);" ascii wide
        
    condition:
        4 of them
}
        
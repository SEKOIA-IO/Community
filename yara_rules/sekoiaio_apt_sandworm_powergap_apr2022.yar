rule sekoiaio_apt_sandworm_powergap_apr2022 {
    meta:
        id = "2a1c7f02-92b3-45b8-a710-253b1a28fe85"
        version = "1.0"
        description = "Detects the POWERGAP malware"
        source = "Sekoia.io"
        creation_date = "2022-04-12"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Get-WmiObject Win32 ComputerSystem).Domain" nocase wide ascii
        $ = "Write-Host \"Error1" nocase wide ascii
        $ = "Write-Host \"Done\" -ForegroundColor Red" nocase wide ascii
        $ = "sysvol\\$Domain\\Poicies\\$GpoGuid" nocase wide ascii
        $ = "Function Start-work" nocase wide ascii
        $ = "Domain: {0}\" -f $Domain)" nocase wide ascii
        
    condition:
        filesize < 3KB and 5 of them
}
        
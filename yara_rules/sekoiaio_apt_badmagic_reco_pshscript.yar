rule sekoiaio_apt_badmagic_reco_pshscript {
    meta:
        id = "7a1b2d31-03b7-4a43-8f4e-ed38ba8e118e"
        version = "1.0"
        description = "Detects BadMagic Reco powershell script"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$headers = @{};"
        $ = "==ARP Cache=="
        $ = "ipconfig.me"
        $ = "-ComputerName $env:computername;"
        
    condition:
        all of them and filesize < 1KB
}
        
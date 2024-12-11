rule sekoiaio_apt_cloudatlas_powertunnel_loader {
    meta:
        id = "f2333b8a-99e9-4f28-b0d8-4f7dc4c648c5"
        version = "1.0"
        description = "Detects the Powershell loader of the PowerTunnel dll"
        source = "Sekoia.io"
        creation_date = "2022-11-29"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "New-Object System.IO.Compression.GzipStream(" ascii fullword
        $ = "[System.Reflection.Assembly]::Load("
        $ = ".ReadBytes("
        $ = ".Service]::StartMain"
        
    condition:
        uint8be(0) == 0x24 and all of them
}
        
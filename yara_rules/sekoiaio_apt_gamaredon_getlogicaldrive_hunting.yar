rule sekoiaio_apt_gamaredon_getlogicaldrive_hunting {
    meta:
        id = "18958ee8-7eb8-43b5-8ad2-be93bb39aa80"
        version = "1.0"
        description = "Detects gamaredon powershell stuff"
        author = "Sekoia.io"
        creation_date = "2023-02-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "VolumeSerialNumber" ascii wide nocase
        $ = "Get-WmiObject" ascii wide nocase
        $ = "]::ToUInt32(" ascii wide nocase
        $ = "DeviceID" ascii wide nocase
        $ = "UploadValues" ascii wide nocase
        $ = "UploadString" ascii wide nocase
        
    condition:
        5 of them and filesize < 500KB
}
        
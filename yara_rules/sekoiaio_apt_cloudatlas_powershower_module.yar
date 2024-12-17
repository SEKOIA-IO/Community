rule sekoiaio_apt_cloudatlas_powershower_module {
    meta:
        id = "dd688058-3d5d-46a7-8380-fe961c3327cd"
        version = "1.0"
        description = "Detects CloudAtlas PowerShower module"
        author = "Sekoia.io"
        creation_date = "2022-11-30"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$env:temp" ascii wide
        $ = "foreach($item in $zip.items" ascii wide
        $ = "echo $result" ascii wide
        $ = "pass.txt" ascii wide
        
    condition:
    all of them and filesize < 10000
}
        
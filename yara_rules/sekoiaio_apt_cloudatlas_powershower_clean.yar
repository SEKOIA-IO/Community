rule sekoiaio_apt_cloudatlas_powershower_clean {
    meta:
        id = "4a7c37df-3f53-4190-a86f-94bba3df628e"
        version = "1.0"
        description = "Detects clean version of PowerShower"
        source = "Sekoia.io"
        creation_date = "2022-12-05"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[io.file]::WriteAllBytes($zipfile" ascii wide
        $ = "System.IO.File]::Exists($p_t" ascii wide
        $ = "HttpRequestP" ascii wide
        $ = "$http_request.getOption(2)" ascii wide
        $ = "HttpRequestP($url)" ascii wide
        
    condition:
    uint8(0) == 0x24 and filesize < 4000 and 4 of them
}
        
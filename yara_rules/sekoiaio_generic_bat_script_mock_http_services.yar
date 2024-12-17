rule sekoiaio_generic_bat_script_mock_http_services {
    meta:
        id = "1cfbe5ba-6304-476d-8308-928100a85c16"
        version = "1.0"
        description = "Generic rule detecting BAT script using mock HTTP services (used by APT28)"
        author = "Sekoia.io"
        creation_date = "2023-09-07"
        classification = "TLP:CLEAR"
        
    strings:
        $bat1 = "@echo off"
        $bat2 = "chcp 65001"
        $ps1 = "WebClient"
        $ps2 = "UploadString"
        $dom1 = "mockbin.org"
        $dom2 = "webhook.site"
        $dom3 = "mocky.io"
        $dom4 = "pipedream.com"
        
    condition:
        (1 of ($bat*) or 1 of ($ps*) ) and 1 of ($dom*)
        and filesize < 2000
}
        
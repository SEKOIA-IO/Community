rule sekoiaio_apt_spikedwine_malicious_hta {
    meta:
        id = "e4526142-d98a-bf35-9d2c-ca2e83638c4b"
        version = "1.0"
        description = "Detects malicious HTA used by SPIKEDWINE"
        source = "Sekoia.io"
        creation_date = "2024-02-29"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "<HTA:APPLICATION ID=" nocase
        $ = "return _0x"
        $ = "font-size: 18px;"
        
    condition:
        all of them
}
        
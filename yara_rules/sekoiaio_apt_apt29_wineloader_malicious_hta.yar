rule sekoiaio_apt_apt29_wineloader_malicious_hta {
    meta:
        id = "5a17d854-0564-4830-a0e5-7867b99716c2"
        version = "1.0"
        description = "Detects malicious HTA used by APT29 to drop Wineloader"
        author = "Sekoia.io"
        creation_date = "2024-03-25"
        classification = "TLP:CLEAR"
        hash = "efafcd00b9157b4146506bd381326f39"
        
    strings:
        $ = "<HTA:APPLICATION ID="
        $ = "var _0x"
        $ = "Date['\\x6e\\x6f\\x77']"
        
    condition:
        all of them
}
        
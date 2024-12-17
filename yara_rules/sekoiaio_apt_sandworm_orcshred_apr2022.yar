rule sekoiaio_apt_sandworm_orcshred_apr2022 {
    meta:
        id = "1a88800c-29e1-4e2c-8374-f5a93dd9fd91"
        version = "1.0"
        description = "Detects the ORCSHRED script"
        author = "Sekoia.io"
        creation_date = "2022-04-12"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "find /etc -name os-release >"
        $ = "/bin/bash /var/"
        $ = "crontab -l >"
        $ = ".sh & disown"
        
    condition:
        3 of them and filesize < 2KB
}
        
rule sekoiaio_apt_uac0154_malicious_html_smuggling {
    meta:
        id = "923d11e5-6332-456d-8aff-ae7fb76193a8"
        version = "1.0"
        description = "UAC-0154 Infection chain"
        source = "Sekoia.io"
        creation_date = "2023-10-02"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Microsoft&reg; HTML Help Workshop 4.1"
        $ = "var a=['"
        $ = ")+b('0x"
        
    condition:
        all of them and filesize < 100KB
}
        
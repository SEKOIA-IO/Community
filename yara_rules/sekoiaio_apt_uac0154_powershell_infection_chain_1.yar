rule sekoiaio_apt_uac0154_powershell_infection_chain_1 {
    meta:
        id = "428eb021-b37f-4db5-8cab-ca2f6dd2e202"
        version = "1.0"
        description = "UAC-0154 Infection chain"
        author = "Sekoia.io"
        creation_date = "2023-10-02"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "command $es ="
        $ = "function isV"
        $ = "doIn;"
        $ = "System.IO.Comp"
        
    condition:
        all of them and filesize < 100KB
}
        
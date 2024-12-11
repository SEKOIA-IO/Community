rule sekoiaio_webshell_icesword_strings {
    meta:
        id = "2c6b3cec-4200-4386-8cd5-4004c9b5b96a"
        version = "1.0"
        description = "Detects icesword webshell"
        source = "Sekoia.io"
        creation_date = "2024-11-22"
        classification = "TLP:CLEAR"
        hash = "0447352827e61696304a8e3d34e1d270"
        hash = "f49cfcda0abdefa385eda7ec7e7a5411"
        hash = "e1518388375ba772ed20503ec6dc6c8a"
        hash = "ecf08cd6af127e01f913354529174a23"
        
    strings:
        $ = "&fsAction=rename&newName="
        $ = "&fsAction=copyto&dstPath="
        
    condition:
        2 of them and filesize < 100KB
}
        
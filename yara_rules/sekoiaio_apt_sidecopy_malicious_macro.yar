rule sekoiaio_apt_sidecopy_malicious_macro {
    meta:
        id = "4b90c33e-48d4-48b6-87a7-c35686e7e913"
        version = "1.0"
        description = "Detects malicious macro used by SideCopy"
        author = "Sekoia.io"
        creation_date = "2023-05-11"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "htmlFile$"
        $ = "Gecko/20100101 Firefox/91.0"
        $ = "Start Menu\\Programs\\Startup\\"
        $ = "Document_Close"
        $ = "ThisDocument" wide
        $ = "ServerXMLHTTP.6.0"
        
    condition:
        uint32be(0) == 0xD0CF11E0 and
        all of them
}
        
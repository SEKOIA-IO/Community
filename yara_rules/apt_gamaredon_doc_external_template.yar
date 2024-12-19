rule apt_gamaredon_doc_external_template {
    meta:
        id = "5f6bbf92-2fdf-428d-af49-2d3e754c29d7"
        version = "1.0"
        description = "Detects malicious templates used by Gamaredon"
        author = "Sekoia.io"
        creation_date = "2023-01-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "USERPROFILE" ascii
        $ = "msxml2" ascii
        $ = "T24gRXJyb3IgUmVzdW1lIE5leHQ" ascii
        
    condition:
        uint32be(0) == 0xd0cf11e0 and filesize < 100KB and all of them
}
        
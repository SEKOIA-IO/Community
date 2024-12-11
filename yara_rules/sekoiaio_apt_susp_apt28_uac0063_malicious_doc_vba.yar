rule sekoiaio_apt_susp_apt28_uac0063_malicious_doc_vba {
    meta:
        id = "58040dbd-09ae-4f9e-940d-3a522e7ccfbb"
        version = "1.0"
        description = "Detects some suspected APT28 document vba"
        source = "Sekoia.io"
        creation_date = "2024-07-25"
        classification = "TLP:CLEAR"
        hash = "fceffb8ae94cef3af21b2943131e94db9e0e67073de48d9d32601a245448d067"
        
    strings:
        $ = { 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 33 31 30 }
        $ = "ThisDocument" wide
        
    condition:
        uint32be(0) == 0xd0cf11e0 and all of them
}
        
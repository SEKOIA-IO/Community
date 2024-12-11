rule sekoiaio_implant_mac_smoothoperator_update_agent {
    meta:
        id = "45a1d0d9-083b-4b4a-b53c-e5d86f804f01"
        version = "1.0"
        description = "UpdateAgent payload delivered by SmoothOperator during the 3CX supply chain attack"
        source = "Sekoia.io"
        creation_date = "2023-07-04"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "3CX Desktop App/.main_storage"
        $ = "3CX Desktop App/config.json"
        $ = "3cx_auth_token_content=%s"
        $ = "3cx_auth_id=%s"
        
    condition:
        uint32be(0)==0xcffaedfe and 2 of them
}
        
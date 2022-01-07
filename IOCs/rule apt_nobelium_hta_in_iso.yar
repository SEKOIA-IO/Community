rule apt_nobelium_hta_in_iso {
    meta:
        id = "874ab41b-5c60-4303-8776-e1c10313a401"
        description = "Matches ISO file embedding HTA"
        hash = "d4fdf63d88da2d59569bb621b18bf5e4"
        hash = "cc08a6df151b8879a4969b2e99086b48"
        version = "1.0"
        creation_date = "2021-12-02"
        modification_date = "2021-12-02"
        classification = "TLP:WHITE"
        source="SEKOIA"
    strings:
        $ = "ImgBurn v2"
        $ = "<hta:application"
    condition:
        all of them and 
        filesize > 1MB and 
        filesize < 3MB 
}

rule sekoiaio_apt_turla_kazuar_variant_2023 {
    meta:
        id = "51e9de6a-5d8a-4627-8063-b70f78e78726"
        version = "1.0"
        description = "New variant of Kazuar observed in 2023"
        author = "Sekoia.io"
        creation_date = "2023-11-03"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "Started from file '" ascii wide
        $s2 = "Zombifying user's" ascii wide
        $s3 = "Result #{0:X16} already exists in {1}" ascii wide
        
    condition:
        uint16(0) == 0x5a4d and 2 of them
}
        
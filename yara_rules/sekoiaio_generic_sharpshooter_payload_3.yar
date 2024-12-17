rule sekoiaio_generic_sharpshooter_payload_3 {
    meta:
        id = "57b3ca9a-59c5-4b28-8eb9-36ff5b3633c2"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        author = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Function RC4(byteMessage, strKey)"
        $ = "Sub Run()"
        $ = "plain = RC4(decoded, "
        $ = "Dim plain"
        
    condition:
        all of them and filesize < 2MB
}
        
rule sekoiaio_generic_sharpshooter_payload_4 {
    meta:
        id = "b8327436-3f3d-441c-86b7-35cd30144dc2"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        source = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Function RC4(byteMessage, strKey)"
        $ = "Set EL = DM.createElement("
        $ = "decodeBase64 = EL.NodeTypedValue"
        $ = "Execute plain"
        
    condition:
        all of them and filesize < 2MB
}
        
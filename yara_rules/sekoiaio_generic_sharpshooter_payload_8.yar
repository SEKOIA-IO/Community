rule sekoiaio_generic_sharpshooter_payload_8 {
    meta:
        id = "e28a1cd3-f7b6-4a55-8229-484e0bbeb7cb"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        author = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Private Function decodeHex(hex)"
        $ = "Dim serialized_obj"
        $ = "decodeHex = EL.NodeTypedValue"
        $ = "d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class)"
        
    condition:
        all of them and filesize < 2MB
}
        
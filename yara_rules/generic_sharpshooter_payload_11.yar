rule generic_sharpshooter_payload_11 {
    meta:
        id = "703d2eb2-c9fd-4891-ba95-f94a8313618e"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        author = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "decodeHex = EL.NodeTypedValue"
        $ = "Private Function decodeHex(hex)"
        $ = "serialized_obj = serialized_obj & "
        $ = "d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class)"
        
    condition:
        all of them and filesize < 2MB
}
        
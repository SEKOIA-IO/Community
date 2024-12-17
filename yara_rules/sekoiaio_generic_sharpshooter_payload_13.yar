rule sekoiaio_generic_sharpshooter_payload_13 {
    meta:
        id = "2d61d7b8-5348-4cc8-9d41-61799b573e3b"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        author = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Private Function decodeHex(hex)"
        $ = "EL.Text = hex "
        $ = "serialized_obj = serialized_obj & "
        $ = "d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class)"
        
    condition:
        all of them and filesize < 2MB
}
        
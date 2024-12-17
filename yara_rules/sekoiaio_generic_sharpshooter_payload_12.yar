rule sekoiaio_generic_sharpshooter_payload_12 {
    meta:
        id = "b69186cf-9825-4d90-be20-7caa9e7de61f"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        author = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "ms.Write(ba, 0, (length / 4) * 3);"
        $ = "var serialized_obj = "
        $ = "d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);"
        $ = "var sc ="
        
    condition:
        all of them and filesize < 2MB
}
        
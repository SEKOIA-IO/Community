rule sekoiaio_generic_sharpshooter_payload_10 {
    meta:
        id = "477f8b92-e231-460c-8660-487d0a97f0e2"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        source = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "length = enc.GetByteCount_2(b);"
        $ = "ms.Write(ba, 0, (length / 4) * 3);"
        $ = "d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);"
        
    condition:
        all of them and filesize < 2MB
}
        
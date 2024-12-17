rule sekoiaio_generic_sharpshooter_payload_7 {
    meta:
        id = "de8069bb-59d7-4753-974a-f77c4b9e9bae"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        author = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "ms.Write(ba, 0, (length / 4) * 3)"
        $ = "var serialized_obj = "
        $ = "var n = fmt.SurrogateSelector;"
        $ = "var o = d.DynamicInvoke(al.ToArray())"
        
    condition:
        all of them and filesize < 2MB
}
        
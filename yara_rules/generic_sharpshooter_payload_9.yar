rule generic_sharpshooter_payload_9 {
    meta:
        id = "e4283d6e-d829-4f21-ba60-9e6232519e54"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        author = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "shell.Environment(\"Process\").Item(\"COMPLUS_Version\")"
        $ = "(enc.GetBytes_4(b), 0, length), 0, ((length / 4) * 3)"
        $ = "DebugPrint Err.Description"
        
    condition:
        all of them and filesize < 2MB
}
        
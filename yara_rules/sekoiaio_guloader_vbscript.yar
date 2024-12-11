rule sekoiaio_guloader_vbscript {
    meta:
        id = "3472e403-b1e6-4fdf-9770-af42d505b556"
        version = "1.0"
        description = "visual basic script delivering GuLoader"
        source = "Sekoia.io"
        creation_date = "2024-02-07"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = " = CreateObject(\"WScript.Shell\")"
        $s2 = " = Join("
        $s3 = ",vbnullstring)"
        
    condition:
        filesize < 20KB and all of them and #s1 > 1 and @s3-@s2 < 16
}
        
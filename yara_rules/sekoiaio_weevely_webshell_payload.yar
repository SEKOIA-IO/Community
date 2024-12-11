rule sekoiaio_weevely_webshell_payload {
    meta:
        id = "f2879c6e-3d1b-41be-8b1d-4f0503fd4b29"
        version = "1.0"
        description = "Detects weevely webshell"
        source = "Sekoia.io"
        creation_date = "2024-04-22"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "<?php include \""
        $s2 = ".basename(__FILE__).\""
        $s3 = ";__HALT_COMPILER(); ?>"
        
    condition:
        all of them and filesize < 1MB and @s1 == 0 and @s2 < @s3
}
        
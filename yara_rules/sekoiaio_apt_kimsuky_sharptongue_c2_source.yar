rule sekoiaio_apt_kimsuky_sharptongue_c2_source {
    meta:
        id = "a2ccf773-511c-4088-8bcf-b923291d024b"
        version = "1.0"
        description = "Detects the PHP code of the SharpTongue C2"
        author = "Sekoia.io"
        creation_date = "2022-07-29"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "<?php"
        $ = "foreach($_GET as $variable => $value)"
        $ = "$chk=$value"
        $ = "base64_encode($ip)"
        
    condition:
        all of them
}
        
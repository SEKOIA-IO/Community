rule sekoiaio_apt_sandworm_awfulshred_obfuscation_apr2022 {
    meta:
        id = "52317e6b-7f2c-4c2a-bcfc-ebb4ab4c728e"
        version = "1.0"
        description = "Detects the AWFULSHRED wiper used by Sandworm"
        source = "Sekoia.io"
        creation_date = "2022-04-12"
        classification = "TLP:CLEAR"
        
    strings:
        $h = "#!/bin/bash"
        $s = { 64 65 63 6c 61 72 65 20 2d 72 20 [8] 3d }
        
    condition:
        $h at 0 and #s > 15
}
        
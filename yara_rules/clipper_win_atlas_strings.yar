rule clipper_win_atlas_strings {
    meta:
        id = "f08c6af6-c325-4f7d-8686-575b25550d6a"
        version = "1.0"
        description = "Detects Atlas Clipper"
        author = "Sekoia.io"
        creation_date = "2023-07-10"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "C:/Users/box/Desktop/ATLAS/ATLAS/main.go" ascii
        $s2 = "ATLAS Clipper" ascii
        $s3 = "Victim: %s" ascii
        $s4 = "Attacker: %s" ascii
        $s5 = "Install Path: %s" ascii
        $s6 = "HWID: %s" ascii
        $s7 = "Install Date: %s" ascii
        $s8 = "https://t.me/atlasclipper_channel" ascii
        
    condition:
        all of them
}
        
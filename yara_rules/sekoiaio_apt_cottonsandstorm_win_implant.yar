rule sekoiaio_apt_cottonsandstorm_win_implant {
    meta:
        id = "04a5255c-f9bb-4612-b0e2-ed0326867055"
        version = "1.0"
        description = "Detects a simple win implant used by Cotton Sandstorm"
        author = "Sekoia.io"
        creation_date = "2024-11-05"
        classification = "TLP:CLEAR"
        hash = "f797d71ed07d6e05556300e4ce0f2927"
        
    strings:
        $ = "DIR =>" wide
        $ = "type=machines&md5=" wide
        $ = "File =>" wide
        $ = "&ip=" wide fullword
        $ = "&un=" wide fullword
        $ = "&cp=" wide fullword
        $ = "myFile\";filename=" ascii
        $ = "ifB75BcjsRBhy2et" ascii
        
    condition:
        uint16be(0) == 0x4d5a and
        4 of them and filesize < 500KB
}
        
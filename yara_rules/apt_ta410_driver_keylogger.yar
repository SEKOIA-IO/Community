rule apt_ta410_driver_keylogger {
    meta:
        id = "0cba1b3b-b93e-41e3-a7df-afd306e6b519"
        version = "1.0"
        description = "Keylogger TA410"
        author = "Sekoia.io"
        creation_date = "2022-10-11"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "namedpipe_keymousespy" ascii wide
        $ = "[`LCTRL]" ascii wide
        $ = "[`RCTRL]" ascii wide
        $ = "[`BREAK]" ascii wide
        $ = "[`NUMLOCK]" ascii wide
        $ = "[`L]" ascii wide
        $ = "[`R]" ascii wide
        $ = "[`M]" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 1MB and
        3 of them
}
        
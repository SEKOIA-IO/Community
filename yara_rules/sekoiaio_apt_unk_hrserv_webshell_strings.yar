rule sekoiaio_apt_unk_hrserv_webshell_strings {
    meta:
        id = "684fd41c-9ea6-4f4e-8db4-82325a2ff80b"
        version = "1.0"
        description = "Detects HrServ web shell based on strings"
        source = "Sekoia.io"
        creation_date = "2023-11-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "open file error!"
        $ = "create file error!"
        $ = "[!] CreatePipe failed."
        $ = "[!] CreateProcess failed."
        $ = "[!] CreateProcess success,no result return."
        $ = "; cadataIV="
        $ = "cadataKey="
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 300KB and
        5 of them
}
        
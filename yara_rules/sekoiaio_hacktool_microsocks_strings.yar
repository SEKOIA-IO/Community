rule sekoiaio_hacktool_microsocks_strings {
    meta:
        id = "20e82008-249b-47a3-885b-7c4b04b31a57"
        version = "1.0"
        description = "Detects Microsocks"
        source = "Sekoia.io"
        creation_date = "2023-12-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "microsocks -1 -i listenip -p port -u user -P password"
        $ = "user/pass, it is added to a whitelist"
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 1MB and
        all of them
}
        
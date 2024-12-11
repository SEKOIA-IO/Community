rule sekoiaio_recotool_adfind_strings {
    meta:
        id = "afca88ef-756a-4b2b-91d7-d18d730e7074"
        version = "1.0"
        description = "Detects Adfind utility based on strings"
        source = "Sekoia.io"
        creation_date = "2022-02-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Find all person objects on cn=ab container of local ADAM instance"
        $ = "IPv6 IP address w/ port is specified [address]:port"
        $ = "Search Global Catalog (port 3268)."
        $ = "~~~ADCSV~~~"
        $ = "adfind -b dc="
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 5MB and
        4 of them
}
        
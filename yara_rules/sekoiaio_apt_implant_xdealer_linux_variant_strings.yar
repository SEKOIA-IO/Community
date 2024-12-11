rule sekoiaio_apt_implant_xdealer_linux_variant_strings {
    meta:
        id = "42690513-753f-4296-b641-4d3b59a5e5e1"
        version = "1.0"
        description = "Detects XDealer linux variant"
        source = "Sekoia.io"
        creation_date = "2024-03-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "ls -l /proc/%s/exe"
        $ = "Linux_%s_%s_%u"
        $ = "chkconfig --add"
        $ = "cmd over return [%s]"
        $ = "touch   -d"
        $ = "%s can't be opened/n"
        $ = "/proc/%s/status"
        
    condition:
        uint32be(0) == 0x7f454c46 and 3 of them and filesize < 1MB
}
        
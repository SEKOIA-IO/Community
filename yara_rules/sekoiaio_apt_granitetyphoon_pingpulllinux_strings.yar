rule sekoiaio_apt_granitetyphoon_pingpulllinux_strings {
    meta:
        id = "ee213206-d9ad-47fa-bea1-61a9d2cfba58"
        version = "1.0"
        description = "Detects PingPull Linux variant"
        source = "Sekoia.io"
        creation_date = "2023-05-25"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "chkconfig --add %s"
        $ = "chkconfig %s on"
        $ = "update-rc.d %s enable"
        $ = "service %s start"
        $ = "respawn limit 10 10"
        $ = "POST /%s HTTP/1.1"
        $ = "PROJECT_%s_%s_%08X"
        $ = "Description=The HTTP(S) Client"
        $ = "exec %s -f"
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 11MB and
        7 of them
}
        
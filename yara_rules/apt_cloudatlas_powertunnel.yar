rule apt_cloudatlas_powertunnel {
    meta:
        id = "04981493-de8b-4662-ae81-8866c182f8b2"
        version = "1.0"
        description = "Detects PowerTunnel DLL of CloudAtlas"
        author = "Sekoia.io"
        creation_date = "2022-11-29"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "BeginGetHostEntry"
        $ = "get_AddressList"
        $ = "time_stop_delay_seconds"
        $ = "<connect><result>{0}</result></connect>"
        $ = "_CorDllMain"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB  and
        all of them
}
        
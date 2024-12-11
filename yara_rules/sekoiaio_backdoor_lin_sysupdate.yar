rule sekoiaio_backdoor_lin_sysupdate {
    meta:
        id = "9cb806cf-4ca1-44d8-809a-58cc5f364fb8"
        version = "1.0"
        description = "Detect the SysUpdate malware"
        source = "Sekoia.io"
        creation_date = "2023-03-01"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "generate guid path=%s"
        $ = "3rd/asio/include/asio/detail/posix_event.hpp"
        $ = "expires_at"
        $ = "%s -f %s"
        $ = "expires_after"
        $ = "-run"
        
    condition:
        uint32(0)==0x464c457f and all of them
}
        
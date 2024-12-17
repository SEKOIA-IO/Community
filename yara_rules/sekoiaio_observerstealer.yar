rule sekoiaio_observerstealer {
    meta:
        id = "52314870-c100-441d-9ccf-07588325a401"
        version = "1.0"
        description = "detection based on the strings"
        author = "Sekoia.io"
        creation_date = "2024-02-01"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "URLOpenBlockingStreamW" ascii
        $s2 = "processGrabber" wide
        $s3 = "grabbers" wide
        $s4 = {2F 00 73}
        $s5 = "UNKNOWN_HWID" ascii
        $s6 = {48 00 57 00 49 00 44}
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 400KB and
        all of them
}
        
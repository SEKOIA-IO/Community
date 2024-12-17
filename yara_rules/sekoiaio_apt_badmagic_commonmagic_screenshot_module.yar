rule sekoiaio_apt_badmagic_commonmagic_screenshot_module {
    meta:
        id = "d1ef0bd1-37dc-405f-b82b-288b1798455c"
        version = "1.0"
        description = "Detects CommonMagic related implants"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "%s_%02d.%02d.%04d_%02d.%02d.%02d.%03d.%s" wide
        $ = "Screenshot" wide
        $ = "\\\\.\\pipe\\PipeDtMd" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        all of them
}
        
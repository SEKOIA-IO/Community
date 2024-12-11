rule sekoiaio_apt_apt29_malicious_rdp_file {
    meta:
        id = "a7b092b5-53a1-4638-a6c1-733d3f063139"
        version = "1.0"
        description = "Detects malicious RDP files"
        source = "Sekoia.io"
        creation_date = "2024-10-25"
        classification = "TLP:CLEAR"
        hash = "db326d934e386059cc56c4e61695128e"
        hash = "b38e7e8bba44bc5619b2689024ad9fca"
        hash = "f58cf55b944f5942f1d120d95140b800"
        hash = "40f957b756096fa6b80f95334ba92034"
        
    strings:
        $ = "RedirectPrinters" wide
        $ = "RedirectCOMPorts" wide
        $ = "RedirectSmartCards" wide
        $ = "RedirectPOSDevices" wide
        $ = "RedirectClipboard" wide
        $ = "DrivesToRedirect" wide
        $ = "full address:s:" wide
        
    condition:
        uint16be(0) == 0xFFFE and
        all of them and filesize < 20KB
}
        
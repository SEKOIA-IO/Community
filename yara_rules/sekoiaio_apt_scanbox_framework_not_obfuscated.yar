rule sekoiaio_apt_scanbox_framework_not_obfuscated {
    meta:
        id = "4790f122-89de-4f7b-a25f-9ac7b1af8333"
        version = "1.0"
        description = "Detects the non obfuscated version of ScanBox"
        source = "Sekoia.io"
        creation_date = "2022-09-01"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "php?m=a&data="
        $ = "php?m=p&data="
        $ = ".fun.split_data = function"
        $ = ".php?data="
        $ = ".php?m=b"
        $ = "basic.apipath"
        $ = ".info.seed ="
        $ = "loadjs ="
        $ = "info.color = screen.colorDepth"
        
    condition:
        5 of them and filesize < 500KB
}
        
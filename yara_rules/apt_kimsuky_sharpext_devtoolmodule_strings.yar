rule apt_kimsuky_sharpext_devtoolmodule_strings {
    meta:
        id = "6f589a9c-344a-4ddc-929e-f123a2c3c187"
        version = "1.0"
        description = "Detects the DevTool module used by SharpExt"
        author = "Sekoia.io"
        creation_date = "2022-07-29"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "packetProc = function" ascii fullword
        $ = "var url = request.request.url" ascii fullword
        $ = "https://mail" ascii fullword
        
    condition:
        all of them and filesize < 50KB
}
        
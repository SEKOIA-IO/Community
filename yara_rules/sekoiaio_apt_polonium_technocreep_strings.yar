rule sekoiaio_apt_polonium_technocreep_strings {
    meta:
        id = "dad79df3-b081-458e-9c14-1d5e2b43ba91"
        version = "1.1"
        description = "Tries to detect TechnoCreep implant"
        author = "Sekoia.io"
        creation_date = "2022-10-12"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "file name : " ascii wide
        $ = "copy to : " ascii wide
        $ = "download" ascii wide
        $ = "persistence" ascii wide
        $ = "/cmdResult created!" ascii wide
        $ = "/downloadsResulat created!" ascii wide
        $ = "Downloading will take minets..." ascii wide
        $ = "powershell -Command \"$c1 = " ascii wide
        $ = "Missing Parameter.. Format of command:" ascii wide
        $ = "File Fath On Target Device Not Exists>" ascii wide
        $ = "/MissingDownloadParameter.txt" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        4 of them
}
        
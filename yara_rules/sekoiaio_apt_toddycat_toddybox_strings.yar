rule sekoiaio_apt_toddycat_toddybox_strings {
    meta:
        id = "fde3df24-ebd7-4327-998e-bddaa08835da"
        version = "1.0"
        description = "Detects ToddyCat's ToddyBox binary"
        source = "Sekoia.io"
        creation_date = "2023-11-20"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Wait a while to upload the next file..."
        $ = "[-] Error Msg: %s"
        $ = "[-] Error Msg: Connect Errors or Proxy Errors"
        $ = "[-] arg missing!"
        $ = "[-] Get module dir failed!"
        $ = "[-] Dir error!"
        $ = "Auto Get Proxy %S"
        $ = "Dropbox-API-Arg"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        all of them
}
        
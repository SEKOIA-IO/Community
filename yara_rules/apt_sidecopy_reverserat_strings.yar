rule apt_sidecopy_reverserat_strings {
    meta:
        id = "383397c9-fd4a-4255-a8f2-27683bdbb7f7"
        version = "1.0"
        description = "Detects SideCopy's ReverseRAT"
        author = "Sekoia.io"
        creation_date = "2023-05-11"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "downloadexe" wide
        $ = "creatdir" wide
        $ = "regnewkey" wide
        $ = "reglist" wide
        $ = "regdelkey" wide
        $ = "clipboardset" wide
        $ = "shellexec" wide
        $ = "SELECT maxclockspeed,  datawidth, name, manufacturer FROM Win32_Processor" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        all of them
}
        
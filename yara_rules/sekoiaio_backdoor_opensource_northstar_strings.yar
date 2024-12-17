rule sekoiaio_backdoor_opensource_northstar_strings {
    meta:
        id = "6bf2f428-ec1a-4115-9c5e-258e9176969a"
        version = "1.0"
        description = "Detects the NorthStar Backdoor strings"
        author = "Sekoia.io"
        creation_date = "2022-08-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "_SAMDUMP.zip" wide
        $ = "northstar" wide
        $ = "smanage.php?sid=" wide
        $ = "File Not Exists" wide
        $ = "<enablecmd or enable cmd>" wide
        $ = "getjuice.php" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        6 of them
}
        
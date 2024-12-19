rule tool_tokenplayer_strings {
    meta:
        id = "74ed8812-f113-47a9-9ff2-6cbe2746ee11"
        version = "1.0"
        description = "Detects TokenPlayer based on strings"
        author = "Sekoia.io"
        creation_date = "2024-11-04"
        classification = "TLP:CLEAR"
        hash = "f01eae4ee3cc03d621be7b0af7d60411"
        
    strings:
        $ = "[*]Spawning Process as user: %s\\%s" wide
        $ = "[-]Target isn't vulnerable!"
        $ = "[+]Process spawned!"
        $ = "[+]Process Spawned"
        $ = "[+]OpenProcessToken() success!"
        $ = "CreateProcessWithLogonW() error : % u"
        $ = "[+]CreateProcessWithLogonW() succeed!"
        $ = "TokenPlayer.pdb"
        
    condition:
        uint16be(0) == 0x4d5a and 
        5 of them and 
        filesize < 500KB
}
        
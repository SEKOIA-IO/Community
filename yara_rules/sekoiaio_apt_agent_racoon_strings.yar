rule sekoiaio_apt_agent_racoon_strings {
    meta:
        id = "ec89f1db-0ba8-48c8-8c1a-c38c410f3e39"
        version = "1.0"
        description = "Detects Agent Racoon used by CL-STA-0002"
        author = "Sekoia.io"
        creation_date = "2023-12-05"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Command failed:" wide
        $ = "Not uploaded:" wide
        $ = "Not downloaded:" wide
        $ = "xn--cc" wide
        $ = "xn--ac" wide
        $ = "xn--bc" wide
        $ = "cmd.exe" wide
        $ = ".xn--" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        all of them
}
        
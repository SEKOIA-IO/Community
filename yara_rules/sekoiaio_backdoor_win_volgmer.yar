rule sekoiaio_backdoor_win_volgmer {
    meta:
        id = "9468a66d-787c-488f-937b-22617c7a2ded"
        version = "1.0"
        description = "Detect the NukeSped variant called Volgmer used by Andariel"
        source = "Sekoia.io"
        creation_date = "2023-09-04"
        classification = "TLP:CLEAR"
        hash1 = "3098e6e7ae23b3b8637677da7bfc0ba720e557e6df71fa54a8ef1579b6746061"
        hash2 = "7339cfa5a67f5a4261c18839ef971d7f96eaf60a46190cab590b439c71c4742b"
        hash3 = "8daa6b20caf4bf384cc7912a73f243ce6e2f07a5cb3b3e95303db931c3fe339f"
        hash4 = "1b88b939e5ec186b2d19aec8f17792d493d74dd6ab3d5a6ddc42bfe78b01aff1"
        
    strings:
        $ = "Fixed" wide
        $ = "CDRom" wide
        $ = "Removable" wide
        $ = "%.2fGB" wide
        $ = "\\*.*" wide
        $ = "Folder" wide
        $ = "%.1fKB" wide
        $ = "%.1fMB" wide
        $ = "%s\\*.*" wide
        $ = "%s\\%s\\%s" wide
        $ = "%s\\%s%s" wide
        $ = "Remote PC" wide
        $ = "%s|%s|%s|%s|%s|%s|" wide
        $ = "%s\\cmd.exe" wide
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        
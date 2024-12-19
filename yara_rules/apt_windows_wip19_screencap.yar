import "pe"
import "hash"
        
rule apt_windows_wip19_screencap {
    meta:
        id = "ebf5d2c5-81c9-45c3-aa61-05870f800f6b"
        version = "1.0"
        description = "Detects ScreenCap resource"
        author = "Sekoia.io"
        creation_date = "2022-10-18"
        classification = "TLP:CLEAR"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
         for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "89f4d0e3f7f3318270aa9c8345c1402202b1a02ffefc03c7a86636e297aa0ffc"
        ) and filesize < 2MB
}
        
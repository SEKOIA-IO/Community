rule sekoiaio_apt_muddywater_manifestation_backdoor_obfuscated {
    meta:
        id = "58df72a1-822c-4b82-904d-1c0124dc7bc1"
        version = "1.0"
        description = "Detects obfuscated Muddys manifestation JScript backdoor"
        author = "Sekoia.io"
        creation_date = "2022-01-13"
        classification = "TLP:CLEAR"
        
    strings:
        $m = { 76 61 72 20 5f 30 78 [4-6] 3d 5b }
        $w = {57 53 63 72 69 70 74 5b 5f 30 78 [4-6] 28 30 78 [2-3] 29 5d 28 30 78 [2-3] 2a 30 78 [2-3] 29 2c }
        $t = "subkeys(key));}"
        
    condition:
        $m at 0 and ($t at (filesize-16) or $w in (filesize-200..filesize))
}
        
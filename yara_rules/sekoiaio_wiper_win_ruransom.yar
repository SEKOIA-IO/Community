import "pe"
import "hash"
        
rule sekoiaio_wiper_win_ruransom {
    meta:
        id = "7bf3694b-c689-482f-88cd-b1f3b86bbc36"
        version = "1.0"
        description = "Detect the RURansom malware"
        author = "Sekoia.io"
        creation_date = "2022-11-21"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "RURansom"
        $ = "AesCrypter"
        $ = "RURansom" wide
        
    condition:
        // Strings
        uint16(0)==0x5A4D and all of them
        
        // Resource
        or for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "e4b6b5b2b293d497ddf373ca9f7e97458328703d2769f451890ac48771c85070"
        )
}
        
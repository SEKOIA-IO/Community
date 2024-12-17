rule sekoiaio_apt_unk_batcopier_strings {
    meta:
        id = "eb76bbd0-a722-4fec-a4a7-c48c70a1880b"
        version = "1.0"
        description = "Detects BatCopier variant"
        author = "Sekoia.io"
        creation_date = "2024-09-06"
        classification = "TLP:CLEAR"
        reference = "https://www.seqrite.com/blog/operation-oxidovy-sophisticated-malware-campaign-targets-czech-officials-using-nato-themed-decoys/"
        
    strings:
        $ = "@echo off"
        $ = "echo F|xcopy"
        $ = "attrib +r +s +h"
        
    condition:
        all of them and filesize < 1KB
}
        
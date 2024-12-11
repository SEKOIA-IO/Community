import "pe"
import "hash"
        
rule sekoiaio_rat_win_romcom_payload {
    meta:
        id = "c391f84c-f0cb-42d8-a8d8-d59725bf74c2"
        version = "1.0"
        description = "Detect the RomCom malware"
        source = "Sekoia.io"
        creation_date = "2022-11-04"
        classification = "TLP:CLEAR"
        
    condition:
        for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "160ed1cdf6e9321cef19cfed6a63b4b5557dd35e174b821bf8a81c4146fa6536"
        )
}
        
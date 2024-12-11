import "pe"
import "hash"
        
rule sekoiaio_backoor_win_gobear {
    meta:
        id = "f922bf1b-652e-4a2f-91e9-76ecd2e3bf6a"
        version = "1.0"
        description = "Detect the GoBear backdoor used by Kimsuky"
        source = "Sekoia.io"
        creation_date = "2024-02-13"
        classification = "TLP:CLEAR"
        reference = "https://medium.com/s2wblog/kimsuky-disguised-as-a-korean-company-signed-with-a-valid-certificate-to-distribute-troll-stealer-cfa5d54314e2"
        
    condition:
        for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "668031f53390dc749971888029911c12d4171534f77c17a962e698bf121d0e20"
        )
}
        
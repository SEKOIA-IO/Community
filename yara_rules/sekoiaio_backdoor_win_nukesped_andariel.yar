import "pe"
import "hash"
        
rule sekoiaio_backdoor_win_nukesped_andariel {
    meta:
        id = "a3601f0b-5782-4546-ac22-8a0514791f8f"
        version = "1.0"
        description = "Detect the NukeSped variant type 1 used by Andariel in October 2023"
        author = "Sekoia.io"
        creation_date = "2023-11-27"
        classification = "TLP:CLEAR"
        reference = "https://asec.ahnlab.com/en/59073/"
        
    condition:
        for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "4ce43c7e358e3951f4c4ebd050d570786cbb473ee353974fc7414e3d753da9f6"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "355485cbe2bec406d60a48d7d8d25c71d9ded3c508c87273d936a92b94720d9b"
        )
}
        
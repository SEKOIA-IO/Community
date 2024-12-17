import "pe"
import "hash"
        
rule sekoiaio_loader_win_abcloader {
    meta:
        id = "c286ce75-a041-478e-a567-4bf1d5e66c01"
        version = "1.0"
        description = "Detect ABCloader"
        author = "Sekoia.io"
        creation_date = "2024-08-19"
        classification = "TLP:CLEAR"
        reference = "https://nsfocusglobal.com/new-apt-group-actor240524-a-closer-look-at-its-cyber-tactics-against-azerbaijan-and-israel/"
        hash = "0d1dca5eaad49c2dbd979e1bf0b5f8d0"
        hash = "9a640889e82407b06c546fea15be668f"
        
    strings:
        $ = "qSii.LI4"
        $ = "Cabinet.dll"
        
    condition:
        uint16be(0) == 0x4d5a and all of them
        
        // Imphash
        or pe.imphash() == "45c6b272631aa9e0c4b2ba675699b803"
        
        // Rich PE header hash
        or hash.md5(pe.rich_signature.clear_data) == "b33158757dc039859e272f4528e10e80"
}
        
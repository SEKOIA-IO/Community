import "hash"
import "pe"
        
rule sekoiaio_ransomware_win_eking_rich_header {
    meta:
        id = "9fe76f89-f27a-4a47-a61c-2d767a1a8acb"
        version = "1.0"
        description = "Detect Eking ransomware using its rich header"
        source = "Sekoia.io"
        creation_date = "2021-10-07"
        classification = "TLP:CLEAR"
        
    condition:
        hash.md5(pe.rich_signature.clear_data) == "256b60751602028612562b73ecdb163c"
}
        
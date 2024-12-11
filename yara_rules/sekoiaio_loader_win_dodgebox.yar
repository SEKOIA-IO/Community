import "pe"
import "hash"
        
rule sekoiaio_loader_win_dodgebox {
    meta:
        id = "8d5f94f3-1add-4f34-ba9e-f8f576c4e5b8"
        version = "1.0"
        description = "Detect the DodgeBox malware using several criteria"
        source = "Sekoia.io"
        creation_date = "2024-07-15"
        classification = "TLP:CLEAR"
        reference = "https://www.zscaler.com/blogs/security-research/dodgebox-deep-dive-updated-arsenal-apt41-part-1"
        hash1 = "c6a3a1ea84251aed908702a1f2a565496d583239c5f467f5dcd0cfc5bfb1a6db"
        hash2 = "33fd050760e251ab932e5ca4311b494ef72cee157b20537ce773420845302e49"
        
    condition:
        // Imphash
        pe.imphash() == "aeea1135af87e6b6b23fa7da995967ea"
        
        // Rich PE header
        or hash.md5(pe.rich_signature.clear_data) == "1c850cf955b35f60ee6c12d01161d95d"
        
        // Sections
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "4a80edcce2a5ac85c3f849172ee89c0f"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "53781057440f51882c38d3a9ef611775"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "801b286d84a97fe919721843ab77210d"
        )
}
        
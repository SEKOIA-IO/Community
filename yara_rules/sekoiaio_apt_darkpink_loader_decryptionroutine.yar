import "hash"
import "pe"
        
rule sekoiaio_apt_darkpink_loader_decryptionroutine {
    meta:
        id = "fefc7b2f-eecc-49dc-84bc-24c45e9ea8f0"
        version = "1.0"
        description = "Detects decryption routine of dark pink loader"
        source = "Sekoia.io"
        creation_date = "2023-01-17"
        classification = "TLP:CLEAR"
        hashs = "3f38860d0f6f0ff1b65219379f8793383cba85b11de1c853192fb2d2ba99e481"
        hashs = "b3f1d6366ebc184f634a240c838b39d729c28b8718b0b9ca6be988a7e446ec42"
        
    strings:
        $chunk_1 = {
        8A 08
        40
        84 C9
        75 ??
        6A 00
        2B C2
        50
        53
        56
        E8 ?? ?? ?? ??
        8A 88 ?? ?? ?? ??
        30 0C 3E
        83 C6 01
        83 D3 00
        78 ??
        7F ??
        81 FE ?? ?? ?? ??
        72 ??
        55
        }
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 3MB and (
            all of them 
            or
            hash.md5(pe.rich_signature.clear_data) == "950c0710dc4cbf6e2cd6b857d25da523"
            or
            for any i in (0..pe.number_of_sections-1) : (
                hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "547e43dd8560fa8b0ca0be9f633bf62d"
            )
        )
}
        
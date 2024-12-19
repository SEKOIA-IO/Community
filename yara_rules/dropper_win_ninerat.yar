import "pe"
import "hash"
        
rule dropper_win_ninerat {
    meta:
        id = "798e3bee-4cee-4647-abda-3c3dcc602f0a"
        version = "1.0"
        description = "NineRAT dropper"
        author = "Sekoia.io"
        creation_date = "2023-12-12"
        classification = "TLP:CLEAR"
        reference = "https://blog.talosintelligence.com/lazarus_new_rats_dlang_and_telegram/"
        hash1 = "534f5612954db99c86baa67ef51a3ad88bc21735bce7bb591afa8a4317c35433"
        hash2 = "f91188d23b14526676706a5c9ead05c1a91ea0b9d6ac902623bc565e1c200a59"
        
    strings:
        $ = "\\x64\\Release\\Dropper.pdb"
        $ = "TelegramRat\\lastest\\Dropper"
        
    condition:
        all of them

        // Imphash
        or pe.imphash() == "92b8e9dea06fd5719e29a510e95b92ac"
        
        // Rich Header
        or hash.md5(pe.rich_signature.clear_data) == "ba1ea20fe779ef0b747e5073c0881a99"
        
        // Section
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "c0471e0a78eef692b567cd89eeaddf08"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "965dc8b7c98325ca3d3371ced8424823"
        )
        
        // Resources
        or for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "bae1db350e313bf7bbd3b2178b20e6f6dd9b0331780099374edae5a99625bc5b"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "1abb447513b4435837029933e722b6ed92222291571a8ce0a306c9f6a335aa19"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "ffbcd5bbe6c02aa5c993886811d7597f020abd6665fc82af133c5756ab72fb0a"
        )
}
        
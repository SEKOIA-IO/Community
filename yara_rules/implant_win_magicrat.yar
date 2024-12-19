import "pe"
import "hash"
        
rule implant_win_magicrat {
    meta:
        id = "74973682-b214-48ee-98c3-f4b6bef76587"
        version = "1.0"
        description = "Detect Lazarus' MagicRAT"
        author = "Sekoia.io"
        creation_date = "2022-09-13"
        classification = "TLP:CLEAR"
        reference = "https://blog.talosintelligence.com/2022/09/lazarus-magicrat.html"
        hash1 = "9dc04153455d054d7e04d46bcd8c13dd1ca16ab2995e518ba9bf33b43008d592"
        hash2 = "c2904dc8bbb569536c742fca0c51a766e836d0da8fac1c1abd99744e9b50164f"
        hash3 = "f6827dc5af661fbb4bf64bc625c78283ef836c6985bb2bfb836bd0c8d5397332"
        
    condition:
        uint16(0)==0x5A4D
        and filesize > 15MB
        and for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "39dfb9f035cba21ffd90973904f90469"
            and pe.sections[i].name == ".qtmetad"
        )
}
        
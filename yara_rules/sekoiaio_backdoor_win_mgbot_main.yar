import "pe"
import "hash"
        
rule sekoiaio_backdoor_win_mgbot_main {
    meta:
        id = "528baa11-58d5-470a-bd6d-963d4ac75d97"
        version = "1.0"
        description = "Detect MgBot main.dll file"
        author = "Sekoia.io"
        creation_date = "2024-03-20"
        classification = "TLP:CLEAR"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/apt-attacks-telecoms-africa-mgbot"
        hash1 = "706c9030c2fa5eb758fa2113df3a7e79257808b3e79e46869d1bf279ed488c36"
        hash2 = "017187a1b6d58c69d90d81055db031f1a7569a3b95743679b21e44ea82cfb6c7"
        
    condition:
        // Imphash
        pe.imphash() == "8e1ee04a99c77bd54c6dc55214ffa2e3"
        
        // Rich header hash
        or hash.md5(pe.rich_signature.clear_data) == "67e8e8b75b981b5c8ff31149dc2c61b2"
        
        // Sections
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "7c6adf9987e6dfbf19b5f156b0314798"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "46fa9f5a035c8ae8de1a0d14150bd5ef"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "f7895f9456f8d51125e6744960c38133"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "5d82bb8a7ef37c417615381b446f715c"
        )
        
        // Resource
        or for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "d7808c6662f098e685040f7c61bc033d9e73002f674de7cf2ffcd6230d60d429"
        )
}
        
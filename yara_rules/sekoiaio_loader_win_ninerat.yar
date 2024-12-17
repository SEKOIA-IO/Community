import "pe"
import "hash"
        
rule sekoiaio_loader_win_ninerat {
    meta:
        id = "b9aa3ddc-7892-402f-b045-182884ee9bad"
        version = "1.0"
        description = "Detect the NineRAT instrumentator"
        author = "Sekoia.io"
        creation_date = "2023-12-12"
        classification = "TLP:CLEAR"
        reference = "https://blog.talosintelligence.com/lazarus_new_rats_dlang_and_telegram/"
        hash1 = "ba8cd92cc059232203bcadee260ddbae273fc4c89b18424974955607476982c4"
        hash2 = "5b02fc3cfb5d74c09cab724b5b54c53a7c07e5766bffe5b1adf782c9e86a8541"
        
    strings:
        $ = "TelegramRat\\lastest\\Dropper"
        $ = "\\Release\\ServiceMid.pdb"
        
    condition:
        // Strings
        all of them
        
        // Imphash
        or pe.imphash() == "104a3dc970a385f64de39e0dad61a9a2"
        
        // Rich Header
        or hash.md5(pe.rich_signature.clear_data) == "aab0aa6b89d883e42be8b65a4e41a139"
        
        // Sections
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "827d5fd4b1a0426037529ee9bba48da0"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "82354f92508dcb33acda01c226de2975"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "ccd0f5d837a6cc05a861f040cbdfe080"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "8d2c169356afe8b53b0ecb83de3084b9"
        )
}
        
import "pe"
import "hash"
        
rule sekoiaio_downloader_win_apt33_tickler {
    meta:
        id = "e1f704d6-d527-479a-8311-d286c06768ac"
        version = "1.0"
        description = "Detect the downloader used by APT33 to diwnload Tickler"
        source = "Sekoia.io"
        creation_date = "2024-08-29"
        classification = "TLP:CLEAR"
        
    condition:
        uint16be(0) == 0x4d5a and
        pe.imphash() == "e43c58659b5b3082387307603478881a"
        or hash.md5(pe.rich_signature.clear_data) == "d30bd7875b225709ecf95bf68dbd435f"
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "d7d2079d0a656c06a03f2c277bb08bda"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "61a1425e6a0d28e29c6fd3d451ac3717"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "916bf96ed3274ce8322d9f370432844f"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "3fab9d4ae989d53cecb2f443b8ce88d0"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "e0967483e074da72ceff4dea3bc17530"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "b4a571736b6646765155ffbd57c27c83"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "35c88ba521887f8fe1b2501f8cd8bd98"
        )
        or for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "636dc666c7496cb3382b029fed53473f181cdc24405886c468e51a103d78b4d4"
        )
}
        
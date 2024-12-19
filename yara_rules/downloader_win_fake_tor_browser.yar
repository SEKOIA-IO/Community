import "pe"
import "hash"
        
rule downloader_win_fake_tor_browser {
    meta:
        id = "6b070ba6-490b-43c2-9a01-65812d829eeb"
        version = "1.0"
        description = "Detect fake TOR browser used to spy Chinese TOR users"
        author = "Sekoia.io"
        creation_date = "2022-10-05"
        classification = "TLP:CLEAR"
        reference = "https://securelist.com/onionpoison-infected-tor-browser-installer-youtube/107627/"
        
    condition:
        for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "7172f95f934574be95c0250fb42b8f51"
        )
}
        
import "pe"
import "hash"
        
rule sekoiaio_implant_win_graphiron_downloader {
    meta:
        id = "c50c4bd2-3828-43bf-b45c-8e911c298536"
        version = "1.0"
        description = "Detect the downloader of Graphiron"
        source = "Sekoia.io"
        creation_date = "2023-02-10"
        classification = "TLP:CLEAR"
        hash1 = "0d0a675516f1ff9247f74df31e90f06b0fea160953e5e3bada5d1c8304cfbe63"
        hash2 = "878450da2e44f5c89ce1af91479b9a9491fe45211fee312354dfe69e967622db"
        
    condition:
        for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "1b614f8d813125f56d2e772ed0ca5dae"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "5c6496d33de5a35bd38ddb12d8b42e03"
        )
        and filesize > 3MB
        and filesize < 6MB
}
        
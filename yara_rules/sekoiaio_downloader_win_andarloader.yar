import "pe"
import "hash"
        
rule sekoiaio_downloader_win_andarloader {
    meta:
        id = "96dd737e-601c-4370-9fa6-4bbafafae203"
        version = "1.0"
        description = "Detect the AndarLoader downloader used by Andariel"
        source = "Sekoia.io"
        creation_date = "2023-09-04"
        classification = "TLP:CLEAR"
        hash1 = "02135f60f3edff0b9baa4c20715ee6a80c94f282079bf879265f5e020d37cf88"
        hash2 = "54ed7a7430974cc2ea694f49f3e637b835dcd24aa19d66af854ad47b87068c92"
        
    condition:
        for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "b338ad077c7f5be85c33def7287198841d55af8cd1ad856fdcd16fdc78f18838"
        )
        and filesize < 100KB
}
        
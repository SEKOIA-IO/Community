rule apt_unk_malicious_lnk {
    meta:
        id = "d2248803-7ddf-4cde-ab6a-78b20e760919"
        version = "1.0"
        description = "Detects a malicious LNK used by an APT"
        author = "Sekoia.io"
        creation_date = "2024-09-06"
        classification = "TLP:CLEAR"
        hash = "a8d7e56eb01a8cf576533db9af2e92ec"
        reference = "https://www.seqrite.com/blog/operation-oxidovy-sophisticated-malware-campaign-targets-czech-officials-using-nato-themed-decoys/"
        
    strings:
        $ = ".pdf.lnkPK"
        $ = ".jfifPK"
        $ = ".batPK"
        $ = ".pdfPK"
        
    condition:
        uint32be(0) == 0x504b0304 and
        all of them
}
        
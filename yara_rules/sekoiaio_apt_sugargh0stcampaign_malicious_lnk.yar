rule sekoiaio_apt_sugargh0stcampaign_malicious_lnk {
    meta:
        id = "4297c150-d125-49b9-8850-fcedf5284ae9"
        version = "1.0"
        description = "Detects malicious LNK used in SugarGh0st campaign"
        author = "Sekoia.io"
        creation_date = "2023-12-01"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "dir /S/b *.lnk " wide
        $ = "%temp%\\*.lnk" wide
        
    condition:
        uint32be(0) == 0x4c000000 and
        filesize < 1MB and
        all of them
}
        
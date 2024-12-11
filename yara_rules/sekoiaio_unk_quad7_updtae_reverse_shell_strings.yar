rule sekoiaio_unk_quad7_updtae_reverse_shell_strings {
    meta:
        id = "02d5394e-734c-4744-b293-1bf96bf1518c"
        version = "1.0"
        description = "Reverse shell used by Quad7 operators"
        source = "Sekoia.io"
        creation_date = "2024-08-19"
        classification = "TLP:CLEAR"
        hash = "40b5ac87ff87634c48fdd2cf64ccb66b"
        hash = "4b8e97260d9ef6ca774675be682d9c8c"
        
    strings:
        $ = "User-Agent: IOT"
        $ = "/iot/post"
        $ = "vender"
        $ = "Response:  %s"
        $ = "cmdNum"
        $ = "UPDTAE"
        $ = "cmdResult"
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 5MB and
        4 of them
}
        
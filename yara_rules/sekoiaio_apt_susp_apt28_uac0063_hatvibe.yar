rule sekoiaio_apt_susp_apt28_uac0063_hatvibe {
    meta:
        id = "c4e04671-e75f-40a4-a489-79c2ce91cf7a"
        version = "1.0"
        description = "Detects some suspected UAC-0063/APT28 HTA loader"
        author = "Sekoia.io"
        creation_date = "2024-07-25"
        classification = "TLP:CLEAR"
        hash = "332d9db35daa83c5ad226b9bf50e992713bc6a69c9ecd52a1223b81e992bc725"
        
    strings:
        $ = "& temp(Mid(" ascii fullword
        $ = ".InnerHTML =" ascii fullword
        $ = "peceert" ascii fullword
        $ = "window.setTimeout" ascii fullword
        $ = "cmdline = Split(" ascii fullword
        
    condition:
        3 of them
}
        
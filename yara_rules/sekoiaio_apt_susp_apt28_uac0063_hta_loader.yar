rule sekoiaio_apt_susp_apt28_uac0063_hta_loader {
    meta:
        id = "8e1889c1-c6ac-4048-9d3a-99ccbbd5435f"
        version = "1.0"
        description = "Detects some suspected APT28 HTA loader"
        source = "Sekoia.io"
        creation_date = "2024-07-25"
        classification = "TLP:CLEAR"
        hash = "332d9db35daa83c5ad226b9bf50e992713bc6a69c9ecd52a1223b81e992bc725"
        
    strings:
        $ = "<HEAD><HTA:APPLICATION ID" ascii fullword
        $ = "id=service>null</span" ascii fullword
        $ = "script Language=\"VBScript.Encode" ascii fullword
        
    condition:
        2 of them
}
        
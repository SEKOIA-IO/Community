rule loader_fakebat_initial_powershell_may24 {
    meta:
        id = "adf0e4fc-fa98-470b-9535-bd30d0bdb3aa"
        version = "1.0"
        description = "Finds FakeBat initial PowerShell script downloading and executing the next-stage payload."
        author = "Sekoia.io"
        creation_date = "2024-05-28"
        modification_date = "2024-06-21"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "='http" wide
        $str02 = "=(iwr -Uri $" wide
        $str03 = " -UserAgent $" wide
        $str04 = " -UseBasicParsing).Content; iex $" wide
        
    condition:
        3 of ($str*) and
        filesize < 1KB and
        true
}
        
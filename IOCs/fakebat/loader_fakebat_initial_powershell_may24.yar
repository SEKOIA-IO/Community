rule loader_fakebat_initial_powershell_may24 {
    meta:
        malware = "FakeBat"
        description = "Finds FakeBat initial PowerShell script downloading and executing the next-stage payload."
        source = "Sekoia.io"
        classification = "TLP:WHITE"

    strings:
        $str01 = "='http" wide
        $str02 = "=(iwr -Uri $" wide
        $str03 = " -UserAgent $" wide
        $str04 = " -UseBasicParsing).Content; iex $" wide

    condition:
        3 of ($str*) and filesize < 1KB
}


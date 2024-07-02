rule loader_fakebat_powershell_fingerprint_may24 {
    meta:
        malware = "FakeBat"
        description = "Finds FakeBat PowerShell script fingerprinting the infected host."
        source = "Sekoia.io"
        classification = "TLP:WHITE"

    strings:
        $str01 = "Get-WmiObject Win32_ComputerSystem" ascii
        $str02 = "-Class AntiVirusProduct" ascii
        $str03 = "status = \"start\"" ascii
        $str04 = " | ConvertTo-Json" ascii
        $str05 = ".FromXmlString(" ascii
        $str06 = " = Invoke-RestMethod -Uri " ascii
        $str07 = ".Exception.Response.StatusCode -eq 'ServiceUnavailable'" ascii
        $str08 = "Invoke-WebRequest -Uri $url -OutFile " ascii
        $str09 = "--batch --yes --passphrase-fd" ascii
        $str10 = "--decrypt --output" ascii
        $str11 = "Invoke-Expression \"tar --extract --file=" ascii

    condition:
        7 of ($str*) and filesize < 10KB
}

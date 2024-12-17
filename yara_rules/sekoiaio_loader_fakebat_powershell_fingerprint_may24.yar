rule sekoiaio_loader_fakebat_powershell_fingerprint_may24 {
    meta:
        id = "7efcf9cf-78fe-400e-abe3-6955c394e358"
        version = "1.0"
        description = "Finds FakeBat PowerShell script fingerprinting the infected host."
        author = "Sekoia.io"
        creation_date = "2024-06-21"
        classification = "TLP:CLEAR"
        
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
        7 of them and
        filesize < 10KB and
        true
}
        
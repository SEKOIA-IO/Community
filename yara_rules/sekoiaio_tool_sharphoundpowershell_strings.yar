rule sekoiaio_tool_sharphoundpowershell_strings {
    meta:
        id = "f27a0bdc-1a8c-43f9-843c-6c8506726f37"
        version = "1.0"
        description = "Detects SharpHound Powershell"
        source = "Sekoia.io"
        creation_date = "2022-08-11"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "function Invoke-BloodHound"
        $ = "$vars.Add($RealDNSName)"
        $ = "$vars.Add($Jitter)"
        $ = "CmdletBinding(PositionalBinding = $false)"
        $ = ").Invoke($Null, @(,$passed))"
        $ = "$EncodedCompressedFile ="
        
    condition:
        filesize < 2MB and 4 of them
}
        
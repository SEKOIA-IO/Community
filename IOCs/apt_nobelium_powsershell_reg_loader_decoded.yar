rule apt_nobelium_powsershell_reg_loader_decoded {
    meta:
        id = "c8ee9c40-fa28-4b9a-98e8-88ccc4a16091"
        description = "Matches the decoded version of the Powershell loader stored in the registry"
        version = "1.0"
        creation_date = "2021-12-07"
        modification_date = "2021-12-07"
        classification = "TLP:WHITE"
        source="SEKOIA"
    strings:
        $x = "FromBase64String((gp HKCU:\\\\SOFTWARE\\\\"
        $y = "Remove-ItemProperty HKCU:\\\\SOFTWARE\\\\"
        $z = "Invoke([IntPtr]::Zero)"
    condition:
        filesize < 3KB and 
        $x and #y == 2 and 
        $z at (filesize-22)
}

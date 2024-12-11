rule sekoiaio_dropper_win_konni_cab {
    meta:
        id = "87a209d5-667a-4a81-837a-660ab98c33c8"
        version = "1.0"
        description = "Detect the CAB files used to drop the KONNI malware"
        source = "Sekoia.io"
        creation_date = "2023-09-26"
        classification = "TLP:CLEAR"
        
    strings:
        $magic = "MSCF"
        $file2 = "check.bat"
        $file3 = "wpnprv64.dll"
        $file4 = "wpnprv32.dll"
        
    condition:
        $magic at 0 and all of ($file*)
}
        
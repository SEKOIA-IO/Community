rule sekoiaio_loader_amadey_standalone_may23 {
    meta:
        version = "1.0"
        description = "Finds standalone samples of Amadey based on characteristic strings"
        author = "Sekoia.io"
        creation_date = "2023-05-17"
        id = "5013586c-5ac3-4c1a-a82e-edce4889eedc"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "\\Amadey\\Release\\Amadey.pdb" ascii
        
        $hex01 = { 6E 74 64 6C 6C 2E 64 6C  6C 00 00 00 72 75 6E 61 73 } //ntdll.dll   runas
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        
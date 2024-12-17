rule sekoiaio_koiloader_powershell_reflective_loading {
    meta:
        id = "9bbe4cea-3e64-4377-bf93-def9fb629734"
        version = "1.0"
        description = "Powershell script loading service.exe (related to Koi Loader)"
        author = "Sekoia.io"
        creation_date = "2024-03-20"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "[Byte[]]$image" ascii fullword
        $s2 = "function GDT"
        $s3 = "function GPA"
        $s4 = "GDT @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])"
        $s5 = "$marshal::GetDelegateForFunctionPointer($CTAddr, $CTDeleg)"
        
    condition:
        $s1 at 0 and 4 of them
}
        
rule sekoiaio_apt_apt29_quarterrig {
    meta:
        id = "e370ed7e-5e12-4add-95f3-3773ea8e2d03"
        version = "1.0"
        description = "Detects QUARTERRIG"
        source = "Sekoia.io"
        creation_date = "2023-04-19"
        classification = "TLP:CLEAR"
        
    strings:
        $str_dll_name = "hijacker.dll"
        $str_import_name = "VCRUNTIME140.dll"
        $op_resolve_and_call_openthread = { 48 [6] 48 [6] 8B D8 E8 [4] [3] 33 D2 B9 FF FF 1F 00 FF D0 }
        $op_resolve_and_call_suspendthread = { E8 [4] 48 8B CB FF D0 83 F8 FF }
        
    condition:
        all of them
}
        
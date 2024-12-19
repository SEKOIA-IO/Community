rule tool_cheat_engine {
    meta:
        id = "51d4246c-f7a1-4589-8f97-bd85d1fe4a0e"
        version = "1.0"
        description = "Detects Cheat Engine driver"
        author = "Sekoia.io"
        creation_date = "2024-07-22"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "ObOpenObjectByName" wide
        $s2 = "PsGetProcessImageFileName" wide
        $s3 = "PsRemoveCreateThreadNotifyRoutine" wide
        $s4 = "PsSuspendProcess" wide
        $s5 = "PsResumeProcess" wide
        $s6  = "\\device\\physicalmemory" wide
        $log = "%sCPU%d.trace" wide
        $ioctl_code = {04 E1 22 00} //base for IOCTL code
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 200KB and all of them
}
        
rule sekoiaio_loader_win_goshellcode {
    meta:
        version = "1.0"
        description = "Finds GoShellcode samples based on the specific strings"
        source = "Sekoia.io"
        reference = "https://github.com/yoda66/GoShellcode/blob/main/gosc.go"
        creation_date = "2023-11-15"
        id = "61346225-325a-4067-a4d6-3b8c001dd380"
        classification = "TLP:CLEAR"
        hash1 = "94445af999055bf7d7cddc0d1d5183ab2776d85285f0522a28fac6c5a6101906"
        hash2 = "fdea8b01b2597ceafe6f08b5fd12cc603b1e3ce2037731c0b6defde6935b1ce0"
        
    strings:
        $str01 = "main.VirtualAlloc" ascii
        $str02 = "main.RtlMoveMemory" ascii
        $str03 = "syscall.Syscall" ascii
        $str04 = "syscall.NewLazyDLL" ascii
        $str05 = "runtime.getGetProcAddress" ascii
        $str06 = "runtime.useAeshash" ascii
        
    condition:
        uint16(0)==0x5A4D and all of ($str*) and filesize < 8MB
}
        
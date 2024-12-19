rule apt_mustangpanda_tonedrop {
    meta:
        id = "39df631c-5766-4804-838f-6c9b800c0cc9"
        version = "1.0"
        description = "TONEDROP strings"
        author = "Sekoia.io"
        creation_date = "2023-06-19"
        classification = "TLP:CLEAR"
        
    strings:
        $window1 = "PROCMON_WINDOW_CLASS"  ascii wide
        $window2 = "OLLYDBG" ascii wide
        $window3 = "WinDbgFrameClass"  ascii wide
        $window4 = "OllyDbg - [CPU]"  ascii wide
        $window5 = "Immunity Debugger - [CPU]"  ascii wide
        
        $errormsg1 = "Unable to open file %s for writing"  ascii wide
        
        $proc_01 = "cheatengine-x86_64.exe" ascii wide
        $proc_02 = "ollydbg.exe" ascii wide
        $proc_03 = "ida.exe" ascii wide
        $proc_04 = "ida64.exe" ascii wide
        $proc_05 = "radare2.exe" ascii wide
        $proc_06 = "x64dbg.exe" ascii wide
        $proc_07 = "procmon.exe" ascii wide
        $proc_08 = "procmon64.exe" ascii wide
        $proc_09 = "procexp.exe" ascii wide
        $proc_10 = "processhacker.exe" ascii wide
        $proc_11 = "pestudio.exe" ascii wide
        $proc_12 = "systracerx32.exe" ascii wide
        $proc_13 = "fiddler.exe" ascii wide
        $proc_14 = "tcpview.exe" ascii wide
        
        $opcodes_check_PEsize = {C7 85 94 FD FF FF 2C 02}
        $opcodes_ShellExecute_1 = {C7 45 BC 53 68 65 6C}
        $opcodes_ShellExecute_2 = {C7 45 C0 6C 45 78 65}
        $opcodes_ShellExecute_3 = {C7 45 C4 63 75 74 65}
        $opcodes_ShellExecute_4 = {66 C7 45 C8 41 00}
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 8MB and 3 of ($window*) and $errormsg1 and 10 of ($proc_*) and 3 of ($opcodes*)
}
        
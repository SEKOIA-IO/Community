import "pe"
import "hash"
        
rule apt_mustang_panda_toneins {
    meta:
        id = "f178217a-ff28-4dd7-9395-f19f3e2e934c"
        version = "1.0"
        description = "Detect the TONEINS implant used by Mustang Panda"
        author = "Sekoia.io"
        creation_date = "2022-11-28"
        classification = "TLP:CLEAR"
        
    strings:
        $rtti1 = ".?AVDNameNode@@"
        $rtti2 = ".?AVcharNode@@"
        $rtti3 = ".?AVpcharNode@@"
        $rtti4 = ".?AVpDNameNode@@"
        $rtti5 = ".?AVDNameStatusNode@@"
        $rtti6 = ".?AVpairNode@@"
        
        $s1 = "DefWindowProcW1222_test" wide ascii
        $s2 = "schtasks /create /sc minute /mo 2 /tn" wide ascii
        $fnv_CreateFile = {CE C9 CA BD}
        $fnv_GetFileSize = {18 81 ED 44}
        $fnv_ReadFile = {43 C9 FC 54}
        $fnv_CloseHandle = {65 00 BA FA}
        $fnv_WriteFile = {4A C4 07 7F}
        $fnv_CreateEventA = {E2 DD D2 F9}
        $fnv_TerminateProcess = {59 EE 4E F8}
        $fnv_GetCurrentProcess = {45 A8 D8 6D}
        $fnv_CreateProcessA = { 09 0A 7C 4A}
        
    condition:
        uint16be(0) == 0x4d5a and
        4 of ($rtti*)
        and
        filesize < 8MB and 
        (    
            for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "69f400d3ff4679294e63fb8a8ca97dbb") 
            or
            (all of ($s*) and 5 of ($fnv*))
        )
}
        
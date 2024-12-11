import "pe"
import "hash"
        
rule sekoiaio_launcher_win_bluehaze {
    meta:
        id = "ccfe0593-0a9f-4369-952e-5cef2f459bb3"
        version = "1.0"
        description = "Detect the BLUEHAZE malware"
        source = "Sekoia.io"
        creation_date = "2022-12-01"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Libraries\\CNNUDTV"
        $ = "cmd.exe /C wuwebv.exe -t -e"
        $ = "cmd.exe /C reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v ACNTV /t REG_SZ /d \"Rundll32.exe SHELL32.DLL,ShellExec_RunDLL"
        
    condition:
        // Strings
        uint16(0)==0x5A4D and 3 of them
        
        // Imphash
        or pe.imphash() == "1b3d8fae6035e34f91baa59643746efe"

        // Rich header
        or hash.md5(pe.rich_signature.clear_data) == "44022b7cefeae4d55edcceb5b9bcd295"

        // Sections
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "1cdcb493593f8793b10e109f6b5b2993"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "276d668ed7d1b46e101425e02a16460f"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "f6a474220add335b5696256235ce8c9c"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "82bccb3330d50080f86ab1aa566cae8e"
        )
}
        
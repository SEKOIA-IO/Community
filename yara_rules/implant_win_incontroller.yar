import "pe"
import "hash"
        
rule implant_win_incontroller {
    meta:
        id = "c346c6ea-c5c0-4e9f-a632-1e8ed0286fbc"
        version = "1.0"
        description = "Detect the INCONTROLLER implant "
        author = "Sekoia.io"
        creation_date = "2022-04-14"
        classification = "TLP:CLEAR"
        hash = "69296ca3575d9bc04ce0250d734d1a83c1348f5b6da756944933af0578bd41d2"
        reference = "https://www.mandiant.com/resources/incontroller-state-sponsored-ics-tool"
        
    strings:
        $ = "AsRockDrv.sys" ascii
        $ = "C:\\Users\\User1\\Desktop\\dev projects\\SignSploit1\\x64\\Release\\AsrDrv_exploit.pdb" ascii
        $ = "found map in %.3f sec physical address : %016I64x" ascii
        $ = "get physical regions error : %x!"
        $ = "Device AsrDrv103 was opened successefuly!" ascii
        $ = "Ioctl handler AsrDrv103 was found successefuly!" ascii
        $ = "cant open the AsrDrv103!" ascii
        $ = "can't read a unsigned driver ! " ascii
        $ = "cant drop and load exploatable driver ! " ascii
        $ = "please set unsigned driver as argument to program!" ascii
        $ = "\\DosDevices\\AsrDrv103" wide
        $t = "This program cannot be run in DOS mode."
        
    condition:
        (uint16(0)==0x5A4D
        and 4 of them
        and filesize < 800KB
        and #t == 2)
        
        // Imphash
        or pe.imphash() == "f139e860bc959a7e65a008399425c090"
        
        // Section MD5
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "a2fe4d32d74354c391a283178f0291e6"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "c33f9caa68fe46c6996a928ba5a38fd6"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "d9a1f1a4d48906da1d9f33eae0f0eaef"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "76426b0209a87fa32ca28e9f2361be67"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "9e63a5064b755925598b8d72ace52dc9"
        )
        
        // Rich Header
        or hash.md5(pe.rich_signature.clear_data) == "140d7fb360dbebb03edab903b5d08285"
}
        
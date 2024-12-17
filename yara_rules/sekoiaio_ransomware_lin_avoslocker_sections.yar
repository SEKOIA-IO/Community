import "elf"
import "hash"
        
rule sekoiaio_ransomware_lin_avoslocker_sections {
    meta:
        id = "3a7bf14d-24fb-47c9-b073-dd734f808983"
        version = "1.0"
        description = "Detect AvosLocker ransomware for Linux by using its section hashes"
        author = "Sekoia.io"
        creation_date = "2022-02-21"
        classification = "TLP:CLEAR"
        hash1 = "0cd7b6ea8857ce827180342a1c955e79c3336a6cf2000244e5cfd4279c5fc1b6"
        hash2 = "7c935dcd672c4854495f41008120288e8e1c144089f1f06a23bd0a0f52a544b1"
        hash3 = "10ab76cd6d6b50d26fde5fe54e8d80fceeb744de8dbafddff470939fac6a98c4"
        
    condition:
        uint32(0)==0x464c457f and
        for any i in (0..elf.number_of_sections-1) : (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "91476dafa5ef669483350538fa6ec4cb")
        and for any i in (0..elf.number_of_sections-1) : (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "c2b21b2556c9d751e203965c825f8a81")
        and for any i in (0..elf.number_of_sections-1) : (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "f858d36231ba743ad8c898d86a67a864")
        and for any i in (0..elf.number_of_sections-1) : (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "7dea362b3fac8e00956a4952a3d4f474")
        and for any i in (0..elf.number_of_sections-1) : (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "489c87d7b1a694980587dfb413fb2afc")
        and for any i in (0..elf.number_of_sections-1) : (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "972e27e9f115278244f5e4ae89dd412a")
        and for any i in (0..elf.number_of_sections-1) : (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "d1f5b688a92b611e1363945fa552a9d7")
}
        
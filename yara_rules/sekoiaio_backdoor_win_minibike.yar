import "pe"
import "hash"
        
rule sekoiaio_backdoor_win_minibike {
    meta:
        id = "d758c41a-279c-4706-9cf3-87740e45f71d"
        version = "1.0"
        description = "Detect the MINIBIKE malware"
        author = "Sekoia.io"
        creation_date = "2024-04-08"
        classification = "TLP:CLEAR"
        hash1 = "985967e245d8fbc722e30371c9ed48c3269ceaa6b9b9b80caf2b95c920c856c2"
        hash2 = "ab0b602665b609392eacdcbfc6c1981f216c19f21e2156a55cf9998eab02227b"
        hash3 = "8e2429d70989bbdd2ea8842dce7c3d790ebe148490ee519b47767557f4a4a733"
        hash4 = "be86b8559a84d97aa1cc9852e60a553f5164477bacfc69b7f3453ad37fb6fd2a"
        hash5 = "78065411e7e8eb205ddae7215a229b7c93bdca5d628670f89caa982238ac7eb6"
        hash6 = "73bf3a5877a7fe16544d15670e3ece034e4826323ba555b3527ad4d061f44ec4"
        reference = "https://www.mandiant.com/resources/blog/suspected-iranian-unc1549-targets-israel-middle-east"
        
    strings:
        $ = "Mini-Junked.dll"
        
    condition:
        // Strings
        uint16(0)==0x5A4D and all of them

        // Imphash
        or pe.imphash() == "75a9ae7d4394abdc30e2a873908fa09d"

        // Rich header
        or hash.md5(pe.rich_signature.clear_data) == "06b2ec5892ac9ad566693b04cf427f3f"

        // Section
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "612006b6f68cd0b8b0d48252dbdef4be"
        )
}
        
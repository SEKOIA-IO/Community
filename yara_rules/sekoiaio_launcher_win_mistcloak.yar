import "hash"
import "pe"
        
rule sekoiaio_launcher_win_mistcloak {
    meta:
        id = "3dbf5efa-d77c-436a-a080-9ac58a78425f"
        version = "1.0"
        description = "Detect the MISTCLOAK malware"
        author = "Sekoia.io"
        creation_date = "2022-12-01"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "\\usb.ini"
        $ = "autorun.inf\\Protection for Autorun\\System Volume Information"
        $ = "G:\\project\\APT\\U"
        $ = "\\new\\u2ec\\Release\\u2ec.pdb"
        $ = "CheckUsbService"
        
    condition:
        // Strings
        uint16(0)==0x5A4D and 3 of them

        // Rich header
        or hash.md5(pe.rich_signature.clear_data) == "0f5082fd7ddd1950fa332a8fa4df052f"

        // Sections
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "0ceac625db1e8405efe45d47486e9e2d"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "6968e6ac7b9c1dfbf40a0b3c4f6f4157"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "e6ed2da41f74e948cba7a002c41c6af5"
        )
}
        
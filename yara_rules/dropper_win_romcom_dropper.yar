import "pe"
import "hash"
        
rule dropper_win_romcom_dropper {
    meta:
        id = "ca1b7114-5a83-4620-a9e2-8228df2be7b1"
        version = "1.0"
        description = "Detect the dropper of RomCom malware"
        author = "Sekoia.io"
        creation_date = "2022-11-04"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "regInjecttNew.dll"
        
    condition:
        //Strings
        uint16(0)==0x5A4D and all of them

        //Imphash
        or pe.imphash()=="643c3d5c721741ad5b90c98c48007038"

        //Sections
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "1c397f4ddafdcfd12bbc41cae45cdf9f"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "b71dc0007c685c790fb2542ddcf284f4"
        )

        //Vhash
        or vhash=="175076655d155515655038z55?z1"
}
        
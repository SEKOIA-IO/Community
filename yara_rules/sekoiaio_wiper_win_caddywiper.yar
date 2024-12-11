import "pe"
import "hash"
        
rule sekoiaio_wiper_win_caddywiper {
    meta:
        id = "869d44ff-79fc-403d-a45d-d33712da5bd0"
        version = "1.0"
        description = "Detect CaddyWiper"
        source = "Sekoia.io"
        creation_date = "2022-03-15"
        classification = "TLP:CLEAR"
        hash1_upx = "b66b179eac03afafdc69f62c207819eceecfbf994c9efa464fda0d2ba44fe2d7"
        hash1 = "ea6a416b320f32261da8dafcf2faf088924f99a3a84f7b43b964637ea87aef72"
        hash2 = "a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea"
        
    strings:
        $ = "NETAPI32.dll" ascii
        $ = "DsRoleGetPrimaryDomainInformation" ascii
        
    condition:
        uint16(0)==0x5A4D
        and filesize > 5KB and filesize < 20KB
        and pe.number_of_sections == 3
        and pe.number_of_resources == 0
        and all of them
        
        // Imphash
        or pe.imphash() == "ea8609d4dad999f73ec4b6f8e7b28e55"
        or pe.imphash() == "bae2d138abe43164fb5e95f313de3d14" //UPX
        
        // PE section
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "f0d4c11521fc3891965534e6c52e128b"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "6be6e878d1e8fed277c5feaf60b57a19" //UPX
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "11f22fc72c3ca7dd6b874bda37c1fe82" //UPX
        )
}
        
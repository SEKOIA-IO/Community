import "pe"
import "hash"
        
rule sekoiaio_installer_win_minibus {
    meta:
        id = "0f7f600d-d93b-4b5a-aa0e-7d91038409e6"
        version = "1.0"
        description = "Detect MINIBUS installer"
        author = "Sekoia.io"
        creation_date = "2024-04-08"
        classification = "TLP:CLEAR"
        hash1 = "26ca51cb067e1fdf1b8ad54ba49883bc5d1945952239aec0c4840754bff76621"
        hash2 = "90fa29cc98be1d715df26d22079bdb8ce1d1fd3ce6a4efb39a4c192134e01020"
        
    strings:
        $ = "\\essential.dat"
        $ = "TorvaldInitial.dll"
        
    condition:
        // Strings
        uint16be(0) == 0x4d5a and 1 of them
        
        // Resources
        or for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "de3fb5d4419eb6b943872dd6e3dd93d19584ef2b158aa3158b3b09f0a9b628ef"
        )
}
        
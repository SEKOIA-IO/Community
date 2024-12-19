import "pe"
import "hash"
        
rule backdoor_win_minibus {
    meta:
        id = "f88bcf15-9a9f-4d84-adc6-db1db55fe93c"
        version = "1.0"
        description = "Detect the MINIBUS backdoor used by UNC1549 since August 2023"
        author = "Sekoia.io"
        creation_date = "2024-02-29"
        classification = "TLP:CLEAR"
        reference = "https://www.mandiant.com/resources/blog/suspected-iranian-unc1549-targets-israel-middle-east"
        
    strings:
        $dll_150_1 = "TorvaldsPersist.dll"
        $dll_150_2 = "FileCoAuth.exe"
        
        $dll_50_1 = "TorvaldInitial.dll"
        $dll_50_2 = "\\essential.dat"
        
    condition:
        // 150KB DLL
        // 10e9d1eaf24ad3c63578d89f8b887adb47700aae02da1532c4842428725e77d6
        // 720afa3e1216a9eb68b66858d50de0326f52afa279ef9ee0521aee98b312382f
        (
            uint16(0)==0x5A4D and all of ($dll_150_*) or
            for any i in (0..pe.number_of_resources-1) : (
                hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "2cf9797b1cfb5795d0fb892b7c371d506a5dd8b7c64fdc82975b3fde6d997df0"
            )
        )
        
        // 50-06KB DLL
        // 26ca51cb067e1fdf1b8ad54ba49883bc5d1945952239aec0c4840754bff76621
        // 90fa29cc98be1d715df26d22079bdb8ce1d1fd3ce6a4efb39a4c192134e01020
        or (
            uint16(0)==0x5A4D and all of ($dll_50_*) or
            for any i in (0..pe.number_of_resources-1) : (
                hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "de3fb5d4419eb6b943872dd6e3dd93d19584ef2b158aa3158b3b09f0a9b628ef"
            )
        )
}
        
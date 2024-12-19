import "pe"
import "hash"
        
rule loader_win_revil_loader {
    meta:
        id = "3c293e87-e2d7-475a-9536-8b991961fa11"
        version = "1.0"
        description = "Detect the REvil loader using DDL side loading. The detected ressource is a legitimate executable used to load the malicious .dll containing the ransomware"
        author = "Sekoia.io"
        creation_date = "2021-07-19"
        classification = "TLP:CLEAR"
        reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/revil-ransomware-uses-dll-sideloading"
        hash1 = "1fe9b489c25bb23b04d9996e8107671edee69bd6f6def2fe7ece38a0fb35f98e"
        hash2 = "50416e50797cf88a48d086e718c003e2d10c3847b1a251669d6f10f8d3546e03"
        hash3 = "66490c59cb9630b53fa3fa7125b5c9511afde38edab4459065938c1974229ca8"
        hash4 = "81d0c71f8b282076cd93fb6bb5bfd3932422d033109e2c92572fc49e4abc2471"
        hash5 = "aae6e388e774180bc3eb96dad5d5bfefd63d0eb7124d68b6991701936801f1c7"
        hash6 = "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e"
        hash7 = "dc6b0e8c1e9c113f0364e1c8370060dee3fcbe25b667ddeca7623a95cd21411f"
        hash8 = "df2d6ef0450660aaae62c429610b964949812df2da1c57646fc29aa51c3f031e"
        
    strings:
        $crypto = ".\\crypto\\" ascii
        
        $dropped_name1 = "MsMpEng.exe" wide
        $dropped_name2 = "mpsvc.dll" ascii
        
    condition:
        all of ($dropped_name*)
        and #crypto > 100
        and for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "33bc14d231a4afaa18f06513766d5f69d8b88f1e697cd127d24fb4b72ad44c7a"
        )
}
        
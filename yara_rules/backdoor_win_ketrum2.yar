import "pe"
import "hash"
        
rule backdoor_win_ketrum2 {
    meta:
        id = "afcc349a-d44b-4b66-b86f-c62e700fa899"
        version = "1.0"
        description = "Detect Ke3chang's Ketrum backdoor version 2"
        author = "Sekoia.io"
        creation_date = "2022-10-19"
        classification = "TLP:CLEAR"
        reference = "https://www.intezer.com/blog/research/the-evolution-of-apt15s-codebase-2020/"
        hash1 = "271384a078f2a2f58e14d7703febae8a28c6e2d7ddb00a3c8d3eead4ea87a0c0"
        hash2 = "aa467945dd7b9b095e592fc96384bb385f2c95d00d5424e42bb6ab09827cb0ce"
        hash3 = "aacaf0d4729dd6fda2e452be763d209f92d107ecf24d8a341947c545de9b7311"
        hash4 = "ac5cb6e17f094068686225075251153e3eb21dc2d1ae744a97ab113cab034a36"
        
    strings:
        $ = "powershell.exe" wide
        $ = "cmd.exe" wide
        $ = "%s\\adult.sft" wide
        $ = "%s\\Notice" wide
        $ = "%s\\Message" wide
        $ = "\\Microsoft\\Media Player" wide
        $ = "Windows\\CurrentVersion\\Explorer\\Shell Folders" wide ascii
        $ = "Windows\\CurrentVersion\\Internet Settings" wide ascii
        
    condition:
        all of them
        
        // Very common resource but appears in all Ketrum samples
        and for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "49a60be4b95b6d30da355a0c124af82b35000bce8f24f957d1c09ead47544a1e"
        )
}
        
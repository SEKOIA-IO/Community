rule apt_GAMAREDON_HTMLSmuggling_Attachment {
    meta:
        id = "a39b6e67-9327-4c5b-902a-b9853cfefc8e"
        version = "1.0"
        intrusion_set = "Gamaredon"
        description = "Detects Gamaredon HTMLSmuggling attachment"
        source = "SEKOIA"
        creation_date = "2023-01-20"
        classification = "TLP:WHITE"
    strings:
        $ = "['at'+'ob'](" ascii
        $ = "['ev'+'al'](" ascii
        $ = "document.querySelectorAll('[" ascii
        $ = "[0].innerHTML.split(' ').join('')))" ascii
    condition:
        filesize < 1MB and
        2 of them
}

rule apt_GAMAREDON_HTMLSmuggling_Attachment_stage2 {
    meta:
        id = "e82335ea-48d5-409c-a270-cfd5a2197c44"
        version = "1.0"
        intrusion_set = "Gamaredon"
        description = "Detects Gamaredon HTMLSmuggling attachment"
        source = "SEKOIA"
        creation_date = "2023-01-20"
        classification = "TLP:WHITE"
    strings:
        $ = ") == -1) die();" ascii 
        $ = "'data:application/x-rar-compressed;base64, ' +" ascii 
        $ = ".appendChild(img);" ascii 
        $ = "['Win32', 'Win64', 'Windows', 'WinCE'].indexOf(" ascii 
        $ = " = navigator[\"platform\"];" ascii 
    condition:
        4 of them and filesize < 1MB
}

rule apt_Gamaredon_GammaLoad_MaliciousLNK {
    meta:
        id = "2612e6c6-0bda-4bfa-a840-aa0a0b4c945b"
        version = "1.0"
        malware = "GammaLoad"
        intrusion_set = "Gamaredon"
        description = "Detects Gamaredon's GammaLoad LNK"
        source = "SEKOIA"
        creation_date = "2022-08-01"
        classification = "TLP:WHITE"
    strings:
    	$mshta = "System32\\mshta.exe"
        $trait = { 0D 0A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0D 0A }
    condition:
        uint32be(0) == 0x4c000000 and
        #trait > 100 and $mshta and
        filesize > 100KB and filesize < 400KB
}

rule apt_Gamaredon_LNKs_farl139_hostname {
    meta:
        id = "f8bb2e6b-e544-46b0-b61b-048fe84e1100"
        version = "1.0"
        intrusion_set = "Gamaredon"
        description = "Detects some hostname used in Gamaredon LNKs"
        source = "SEKOIA"
        creation_date = "2023-01-20"
        classification = "TLP:WHITE"
    strings:
        $ = "desktop-farl139"
    condition:
        uint32be(0) == 0x4c000000
        and all of them 
        and filesize < 10KB
}
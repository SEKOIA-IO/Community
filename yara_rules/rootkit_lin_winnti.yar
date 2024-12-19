import "elf"
import "hash"
        
rule rootkit_lin_winnti {
    meta:
        id = "c800038e-7f8a-4f24-bf0b-06aba6a828cb"
        version = "1.0"
        description = "Rootkit used by Winnti"
        author = "Sekoia.io"
        creation_date = "2024-05-22"
        classification = "TLP:CLEAR"
        reference = "https://x.com/naumovax/status/1792902386295394629"
        hash1 = "161344ae61278e09eacb1c76508cda45555eee109e6d6a031716a096ab5c84f3"
        hash2 = "bb56e088739b281c9f56b4fa3fa4d285e45b32c4f9f06b647d7e8cb916054e1a"
        hash3 = "777c1fda4008f122ff3aef9e80b5b5720c9f2dbc3d7e708277e2ccad1afd8cc5"
        hash4 = "9c770b12a2da76c41f921f49a22d7bc6b5a1166875b9dc732bc7c05b6ae39241"
        
    strings:
        $ = "[CDATA[%s]]></name><type>%o</type><perm>%o</perm><user>%s:%s</user><size>%llu</size><time>%s</time></LIST>"
        $ = "HideFile"
        $ = "DownThread"
        $ = "PortforwardThread"
        $ = "HidePidPort"
        $ = "DownFile"
        $ = "ReadReConnConf"
        $ = "DecRemotePort"
        $ = "DecRemoteIP"
        
    condition:
        uint32(0)==0x464c457f 
        and 6 of them
        and for any i in (0..elf.number_of_sections-1) : (
            hash.md5(elf.sections[i].offset, elf.sections[i].size) == "7dea362b3fac8e00956a4952a3d4f474"
        )
}
        
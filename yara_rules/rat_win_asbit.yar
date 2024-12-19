rule rat_win_asbit {
    meta:
        version = "1.0"
        description = "Finds Asbit samples based on characteristic strings"
        author = "Sekoia.io"
        reference = "https://blogs.juniper.net/en-us/threat-research/asbit-an-emerging-remote-desktop-trojan"
        creation_date = "2022-09-19"
        id = "b2d60eff-3dc8-4857-a0ea-d4fcd34c40bc"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "/build?project=libexpat&_={0}" wide
        $str02 = "/resolve?name={0}&short=true&_={1}" wide
        $str03 = "/c ping 127.0.0.1 & del {0} /q & del /a:H {0} /q" wide
        
    condition:
        uint16(0)==0x5A4D and 1 of them
}
        
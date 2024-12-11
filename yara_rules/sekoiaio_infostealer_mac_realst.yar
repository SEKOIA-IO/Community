rule sekoiaio_infostealer_mac_realst {
    meta:
        id = "16a89317-c92d-4e13-94d3-a85a915f52e5"
        version = "1.0"
        description = "Finds Realst Stealer samples based on specific strings"
        source = "Sekoia.io"
        reference = "https://iamdeadlyz.gitbook.io/malware-research/july-2023/fake-blockchain-games-deliver-redline-stealer-and-realst-stealer-a-new-macos-infostealer-malware#realst-stealer-macos"
        creation_date = "2023-09-11"
        classification = "TLP:CLEAR"
        
    strings:
        $str00 = "realst@" ascii
        $str01 = "IP:" ascii
        $str02 = "OS:" ascii
        $str03 = "PC PASSWORD:" ascii
        $str04 = "Cookies:" ascii
        $str05 = "Wallets:" ascii
        $str06 = "Apps:" ascii
        $str07 = "USERNAME: ]" ascii
        $str08 = "FILENAME:" ascii
        $str09 = "multipart/form-data; boundary=" ascii
        $str10 = "src/browsers/firefox/modules/decryptors.rs" ascii
        $str11 = "{\"event_id\":\"" ascii
        $str12 = "..browsers..firefox..modules..data_stealers.." ascii
        $str13 = "..browsers..chromium..modules..key_stealers.." ascii
        $str14 = "..browsers..firefox..modules..decryptors.." ascii
        $str15 = "url: , login: , password:" ascii
        
    condition:
        (uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca) //macho
        and 13 of ($str*)
}
        
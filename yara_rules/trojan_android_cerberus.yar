rule trojan_android_cerberus {
    meta:
        id = "3ea398bd-a80c-40f4-ad52-73b528add4ad"
        author = "Sekoia.io"
        creation_date = "2022-01-24"
        description = "Detect samples of the Android banking trojan Cerberus, or its family"
        version = "1.0"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "assets/neurax.txt"
        $str1 = "assets/Card_UpPotency_UI.json"
        $str2 = "assets/Card_SignetFoster_UI.json"
        $str3 = "assets/Gene_EmpathyTrainer.png"
        
        $bin0 = "assets/180417.bin"
        $bin1 = "assets/180513.bin"
        $bin2 = "assets/180527.bin"
        $bin3 = "assets/180528.bin"
        
    condition:
        uint32be(0) == 0x504B0304
        and filesize > 1MB
        and filesize < 4MB
        and 3 of ($str*) and 3 of ($bin*)
}
        
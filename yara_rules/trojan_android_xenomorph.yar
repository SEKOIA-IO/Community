rule trojan_android_xenomorph {
    meta:
        id = "ec65ca1b-e71f-4772-8be0-2a2b6a690987"
        author = "Sekoia.io"
        creation_date = "2022-02-25"
        description = "Detect samples of the Android banking trojan Xenomorph"
        version = "1.0"
        classification = "TLP:CLEAR"
        
    strings:
        $ass0 = "assets/shadows/knife_shadow_"
        $ass1 = "assets/knife_"
        $ass2 = "okhttp3"
        
    condition:
        uint32be(0) == 0x504B0304
        and filesize > 1MB
        and filesize < 4MB
        and #ass0 > 10 and #ass1 > 10 and $ass2
}
        
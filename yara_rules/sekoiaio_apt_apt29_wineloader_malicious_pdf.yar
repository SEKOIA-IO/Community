rule sekoiaio_apt_apt29_wineloader_malicious_pdf {
    meta:
        id = "b1db731e-471e-493a-b76c-38d2808ccac9"
        version = "1.0"
        description = "Detects malicious PDF used by APT29 to drop Wineloader"
        source = "Sekoia.io"
        creation_date = "2024-03-25"
        classification = "TLP:CLEAR"
        hash = "9712217ff3597468b48cdf45da588005de3a725ba554789bb7e5ae1b0f7c02a7"
        hash = "3739b2eae11c8367b576869b68d502b97676fb68d18cc0045f661fbe354afcb9"
        
    strings:
        $s1 = "<</Type/Annot/Subtype/Link/Border[0 0 0]/Rect["
        $s2 = "/A<</Type/Action/S/URI/URI("
        $s3 = { 2f [2-10] 2e 70 68 70 29 3e 3e }
        $s4 = "JamrulNormal"
        
    condition:
        uint32be(0) == 0x25504446 and
        $s2 in (@s1..@s3) and $s4
}
        
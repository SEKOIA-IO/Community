rule sekoiaio_apt_gamaredon_gammaload_malicioushta {
    meta:
        id = "e5e502db-7f37-40f2-9ba3-81e158e767db"
        version = "1.0"
        description = "Detects Gamaredon's GammaLoad HTA"
        author = "Sekoia.io"
        creation_date = "2022-08-01"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "platform = window.navigator?.userAgentData?.platform" ascii fullword
        $s2 = "'Win32', 'Win64', 'Windows', 'WinCE'" ascii
        $s3 = "dcreate.download ="
        $s4 = "dcreate.href = 'data:application/x-rar-compressed;base64"
        $s5 = "= \"UmFyI"
        
    condition:
        uint32be(0) == 0x3c68746d and
        filesize < 400KB and filesize > 50KB and
        4 of them
}
        
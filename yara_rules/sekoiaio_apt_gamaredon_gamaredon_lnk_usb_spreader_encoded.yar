rule sekoiaio_apt_gamaredon_gamaredon_lnk_usb_spreader_encoded {
    meta:
        id = "e42bb654-d1aa-4219-b3da-dd4053d59a83"
        version = "1.0"
        description = "Detects encoded version of Gamaredon LNK USB Spreader"
        source = "Sekoia.io"
        hash = "28358a4a6acdcdfc6d41ea642220ef98c63b9c3ef2268449bb02d2e2e71e7c01"
        creation_date = "2023-06-19"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(" ascii
        $s2 = " 1000000){" base64
        $s3 = "+\"\\$" base64
        $s4 = ",3\";" base64
        
    condition:
        $s1 at 0 and 3 of them and filesize < 4000
}
        
rule sekoiaio_darkriver_encodedurl {
    meta:
        id = "60f1676f-dade-4376-9980-f510dff52ae5"
        version = "1.0"
        description = "Detects encoding URL inside docx documents"
        source = "Sekoia.io"
        creation_date = "2023-10-10"
        classification = "TLP:CLEAR"
        hash1 = "5c9551388213f54c4b54cd42ccb034d8d9173a4bbfcf8b666e0db8df929762e7"
        hash1 = "13de9f39b1ad232e704b5e0b5051800fcd844e9f661185ace8287a23e9b3868e"
        hash1 = "3b05e89ff2338472cc493d59bae450338effd29f0ed7d46fb999709e63cf2472"
        
    strings:
        $s1 = "&#109;&#104;&#116;&#109;&#108;&#58;&#104;&#116;&#116;&#112;"
        $s2 = "&#38;&#95;&#116;&#115;&#61;"
        $header = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        
    condition:
        filesize < 500KB and
        any of ($s*) and $header at 0
}
        
rule sekoiaio_apt_apt37_malicious_hta_file {
    meta:
        id = "22a98c27-8ff4-4760-b505-f8eacf4dabda"
        version = "1.0"
        description = "Detects malicious APT37 files"
        source = "Sekoia.io"
        creation_date = "2023-03-06"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "<HTML>" nocase
        $s2 = " UwB0AGEAcgB0AC0AUwBs" ascii
        $s3 = "= new ActiveXObject(" ascii
        $s4 = "\", \"\", \"open\", 0);" ascii
        $s5 = ".moveTo(" ascii
        $s6 = "self.close();"
        
    condition:
        $s1 at 0 and all of them and filesize < 1MB
}
        
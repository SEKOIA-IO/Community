rule apt_kimsuky_toddlershark_obfuscated {
    meta:
        id = "9ab82466-4f38-4597-b75b-13252e180c70"
        version = "1.0"
        description = "Detects obfuscated version of Kimsuky TODDLERSHARK vbs malware"
        author = "Sekoia.io"
        creation_date = "2024-03-06"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = { 3a 20 [3-10] 20 3d 20 22 [3-30] 22 3a }
        $s2 = { 45 78 65 63 75 74 65 28  [3-15] 28 22 }
        $s3 = { 50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 [3-15] 28 42 79 56 61 6c 20 [3-15] 29 3a }
        $s4 = "& Chr(\"&H\" & Mid("
        
    condition:
        #s4 == 1 and #s3 == 1 and #s2 == 1 and #s1 > 20 and filesize < 1MB
}
        
rule sekoiaio_ransomware_win_avoslocker {
    meta:
        id = "fc5c2483-48cb-4282-b6cb-ac728b948607"
        version = "1.0"
        description = "Detect AvosLocker ransomware (2021-07)"
        source = "Sekoia.io"
        creation_date = "2021-08-03"
        classification = "TLP:CLEAR"
        hash6 = "f810deb1ba171cea5b595c6d3f816127fb182833f7a08a98de93226d4f6a336f"
        hash7 = "c0a42741eef72991d9d0ee8b6c0531fc19151457a8b59bdcf7b6373d1fe56e02"
        hash8 = "84d94c032543e8797a514323b0b8fd8bd69b4183f17351628b13d1464093af2d"
        
    strings:
        $s1 = "cryptopp850\\rijndael_simd.cpp" ascii
        $s2 = "cryptopp850\\sha_simd.cpp" ascii
        $s3 = "cryptopp850\\gf2n_simd.cpp" ascii
        $s4 = "cryptopp850\\sse_simd.cpp" ascii
        
    condition:
        all of them
        and uint16(0)==0x5A4D
        and filesize > 900KB
        and filesize < 950KB
}
        
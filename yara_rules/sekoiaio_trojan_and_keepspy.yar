rule sekoiaio_trojan_and_keepspy {
    meta:
        id = "9390e7c8-a996-45cc-b642-c23d4b7dcf34"
        version = "1.0"
        description = "Finds KeepSpy samples based on specific strings"
        source = "Sekoia.io"
        creation_date = "2023-06-28"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "Characters entered %1$d of %2$d" ascii
        $str02 = "com.google.android.material.behavior.HideBottomViewOnScrollBehavior" ascii
        $str03 = "com/j256/ormlite/core/VERSION.txt" ascii
        $str04 = "res/raw/empty.wav" ascii
        $str05 = "res/mipmap/ic_launcher.png" ascii
        $str06 = "res/interpolator/fast_out_slow_in.xml" ascii
        $str07 = "OnePixelActivity" ascii
        
    condition:
        uint32be(0) == 0x504B0304 and 6 of them 
        and filesize > 2MB
}
        
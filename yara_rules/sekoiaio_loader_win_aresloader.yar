rule sekoiaio_loader_win_aresloader {
    meta:
        version = "1.0"
        description = "Finds AresLoader samples based on characteristic strings"
        source = "Sekoia.io"
        reference = "https://blog.cyble.com/2023/04/28/citrix-users-at-risk-aresloader-spreading-through-disguised-gitlab-repo/"
        creation_date = "2023-05-02"
        id = "bf5070fc-c8ca-4458-8702-cd1830667b7a"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "{\\\"ip\\\": '%s', \\\"UID\\\": '%s', \\\"geo\\\": '%s', \\\"service\\\": '%s', \\\"owner_token\\\": '%s'}" ascii
        $str02 = "AresLdr_v_3" ascii
        $str03 = "https://ipinfo.io/ip" ascii
        $str04 = "C:\\Users\\%s\\AppData\\Roaming\\%s\\%s" ascii
        $str05 = "/manager/payload" ascii
        $str06 = "/manager/loader" ascii
        $str07 = "/manager/legit" ascii
        $str08 = "/manager/hvnc" ascii
        $str09 = "C%p %d V=%0X w=%ld %s" ascii
        $str10 = "rundll32.exe %s,%s" ascii
        $str11 = "%startinfo" ascii
        $str12 = "%managedapp" ascii
        $str13 = "%has_cctor" ascii
        
    condition:
        uint16(0)==0x5A4D and 5 of them
}
        
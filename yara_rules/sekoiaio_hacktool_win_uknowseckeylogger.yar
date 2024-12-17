rule sekoiaio_hacktool_win_uknowseckeylogger {
    meta:
        version = "1.0"
        description = "Detect the uknowsec keylogger based on strings"
        author = "Sekoia.io"
        creation_date = "2022-10-05"
        id = "ab08136d-b1f3-4e64-b73c-e6344b610f91"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "github.com/atotto/clipboard" ascii
        $str1 = "github.com/TheTitanrain/w32" ascii
        $str2 = "github.com/aliyun/aliyun-oss-go-sdk" ascii
        $str3 = "golang.org/x/sys" ascii
        $str4 = "golang.org/x/time" ascii
        $str5 = "WSARecvWSASend[Print][Right][Shift][Sleep][debug][error]" ascii
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        
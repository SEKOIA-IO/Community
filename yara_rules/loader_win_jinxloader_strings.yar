rule loader_win_jinxloader_strings {
    meta:
        version = "1.0"
        description = "Finds JinxLoader samples based on the specific strings"
        author = "Sekoia.io"
        creation_date = "2023-12-04"
        id = "fd2f7e8c-f4a8-4452-bbc6-e03790f8ed89"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "JinxV2" ascii
        $str02 = "main.main.func1" ascii
        $str03 = "go.shape.struct" ascii
        
        $str04 = ".glob..func" ascii
        
    condition:
        uint16(0)==0x5A4D and all of them and #str04 > 100
        and filesize > 8MB
}
        
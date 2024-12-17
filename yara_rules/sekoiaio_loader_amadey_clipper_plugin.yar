rule sekoiaio_loader_amadey_clipper_plugin {
    meta:
        version = "1.0"
        description = "Finds Amadey's clipper plugin based on characteristic strings"
        author = "Sekoia.io"
        creation_date = "2023-05-16"
        id = "487b6657-8834-45ee-8fd4-03df9c0dd7be"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "CLIPPERDLL.dll" ascii
        $str02 = "??4CClipperDLL@@QAEAAV0@$$QAV0@@Z" ascii
        $str03 = "??4CClipperDLL@@QAEAAV0@ABV0@@Z" ascii
        $str04 = "Main" ascii fullword
        $str05 = "OpenClipboard" ascii
        $str06 = "GetClipboardData" ascii
        $str07 = "D:\\Mktmp\\Amadey\\ClipperDLL\\Release\\CLIPPERDLL.pdb" ascii
        
    condition:
        uint16(0)==0x5A4D and 5 of them
}
        
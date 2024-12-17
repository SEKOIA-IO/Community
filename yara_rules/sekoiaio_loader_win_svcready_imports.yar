import "pe"
        
rule sekoiaio_loader_win_svcready_imports {
    meta:
        id = "e89aa736-acee-4881-b367-a9abfe9784ec"
        version = "1.0"
        description = "Finds samples of the SVCReady loader"
        author = "Sekoia.io"
        reference = "https://threatresearch.ext.hp.com/svcready-a-new-loader-reveals-itself/"
        creation_date = "2022-06-08"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "Svc:RunPEDllNative" ascii
        $str1 = "RunPEDllNative::" ascii
        
    condition:
        uint16(0)==0x5A4D and
        filesize > 200KB and filesize < 2MB and
        pe.imports("GDI32.dll", "Ellipse") and
        pe.imports("GDI32.dll", "SelectObject") and
        pe.imports("GDI32.dll", "GetStockObject") and
        pe.imports("GDI32.dll") == 3 and
        all of them
}
        
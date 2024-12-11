import "dotnet"
        
rule sekoiaio_dotnet_injector_new_payload {
    meta:
        id = "b0a1d471-5381-4fa8-8563-7e72ecd15bed"
        version = "1.0"
        description = "New dotnet injector"
        source = "Sekoia.io"
        creation_date = "2022-12-21"
        classification = "TLP:CLEAR"
        
    strings:
        $f1 = "DownloadFile" ascii
        $f2 = "StreamReader" ascii
        $f3 = "ReadToEnd" ascii
        $f4 = "Reverse" ascii
        $f5 = "Load" ascii
        $f6 = "StringToByteArray" ascii
        $s1 = "Admin" wide
        $s2 = "User" wide
        $p1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" wide
        $p2 = ".lnk" wide
        
    condition:
        filesize < 300KB and
        all of ($f*) and
        all of ($s*) and
        all of ($p*) and
        dotnet.is_dotnet
}
        
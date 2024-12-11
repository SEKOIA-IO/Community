rule sekoiaio_tool_ladon_strings {
    meta:
        id = "7f06f755-a103-4e74-a9df-136355775233"
        version = "1.0"
        description = "Detects Ladon based on strings"
        source = "Sekoia.io"
        creation_date = "2024-06-03"
        classification = "TLP:CLEAR"
        
    strings:
        $a1 = ".GetType('Ladon.Scan')"
        $a2 = "= New-object Byte[]("
        $a3 = "([IO.MemoryStream][Convert]::FromBase64String("
        
        $b1 = "DeflateStream([IO.MemoryStream][Convert]::FromBase64String("
        $b2 = "))}}}}}}}}}"
        $b3 = "::Main(@($"
        $b4 = "))} else {If("
        $b5 = "= [Reflection.Assembly]::Load("
        
        $c1 = "ChatLadon.Form1.resources"
        $c2 = "ChatLadon.Properties.Resources.resources"
        $c3 = "WebClientUploadEvent"
        $c4 = "WebClientDownloadEvent"
        $c5 = "K8robot"
        $c6 = "K8IPselect"
        
        $d1 = "loadASM"
        $d2 = "ConsoleApp1.exe"
        $d3 = "K8Ladon"
        
        $e1 = "get_network_16px_1219919_easyicon_net"
        $e2 = "K8gege"
        $e3 = "LadonExpBuild"
        
        $f1 = "Ladon url.txt CitrixVer"
        $f2 = "Ladon MssqlCmd"
        $f3 = "Example: Ladon "
        $f4 = "k8gege.org"
        $f5 = "K8crack"
        
        $g1 = "LadonStudy.exe"
        $g2 = "LadonStudy.frmMain.resources"
        $g3 = "LadonStudy.Properties.Resources.resources"
        $g4 = "K8gege"
        
        $h1 = "LadonShell.exe" wide
        $h2 = "ForceRemove"
        $h3 = "GetUserObjectInformationA"
        
    condition:
        ( all of ($a*) or 
        all of ($b*) or 
        all of ($c*) or 
        all of ($d*) or 
        all of ($e*) or 
        all of ($f*) or 
        all of ($g*) or 
        all of ($h*) )
        and filesize < 5MB
}
        
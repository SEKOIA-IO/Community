import "magic"
        
rule sekoiaio_icedid_chm_ttp {
    meta:
        id = "cae771d4-a9cf-4325-81b3-c00090cbc05e"
        version = "1.0"
        description = "IcedID campaign delivering ISO file with CHM attack chain"
        author = "Sekoia.io"
        creation_date = "2022-09-28"
        classification = "TLP:CLEAR"
        
    strings:
        $hta1 = "<HTA:APPLICATION " ascii
        $hta2 = "<script language=\"Javascript\">" ascii
        $hta3 = "ActiveXObject" ascii
        $hta4 = "cmd /c rundll32 \\" ascii
        $chm1 = "CHM" ascii
        $chm2 = ".htm" ascii
        
    condition:
        3 of ($hta*) and all of ($chm*) and magic.mime_type() == "application/x-iso9660-image" and filesize > 500KB
}
        
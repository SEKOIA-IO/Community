rule implant_macos_geacon {
    meta:
        id = "a7784bfa-66a7-47df-b88b-d98217d8cca5"
        version = "1.0"
        description = "Finds Geacon samples based on specific strings"
        author = "Sekoia.io"
        reference = "https://www.sentinelone.com/blog/geacon-brings-cobalt-strike-capabilities-to-macos-threat-actors/"
        creation_date = "2024-01-11"
        classification = "TLP:CLEAR"
        
    strings:
        $gea01 = "geacon/config.init" ascii
        $gea02 = "geacon_pro-master/config/config.go" ascii
        $gea03 = "geacon_plus-main/config/config.go" ascii
        $gea04 = "command type %d is not support by geacon now" ascii
        $gea05 = "main/sysinfo.GeaconID" ascii
        
        $str01 = "command.StealToken" ascii
        $str02 = "command.MakeToken" ascii
        $str03 = "command/misc.go" ascii
        $str04 = "config/c2profile.go" ascii
        $str05 = "crypt.AesCBCDecrypt" ascii
        $str06 = "packet.File_Browse" ascii
        $str07 = "packet.FirstBlood" ascii
        $str08 = "packet.ParseCommandShell" ascii
        $str09 = "packet.ParseCommandUpload" ascii
        $str10 = "packet.PushResult" ascii
        $str11 = "sysinfo.GetComputerName" ascii
        $str12 = "sysinfo.IsOSX64" ascii
        $str13 = "util..inittask" ascii
        
    condition:
        uint32(0) == 0xFEEDFACF and
        ((1 of ($gea*) and 2 of ($str*)) or 8 of ($str*))
}
        
rule sekoiaio_apt_gelsemium_firewood_backdoor {
    meta:
        id = "93670c07-9edd-4ea2-b8ed-6fee625491f4"
        version = "1.0"
        description = "Detects Gelsemium's FireWood backdoor"
        source = "Sekoia.io"
        creation_date = "2024-11-22"
        classification = "TLP:CLEAR"
        hash = "2251bc7910fe46fd0baf8bc05599bdcf"
        
    strings:
        $ = "root dir:%s"
        $ = "df -h|grep 'dev' |grep -v none|awk '/dev/{print $6}'"
        $ = "rm -rf ../lib/%s"
        $ = "Total Disk space:%luG, Free Disk spae:%luG"
        
    condition:
        uint32be(0) == 0x7f454c46 and 
        filesize < 1MB and
        all of them
}
        
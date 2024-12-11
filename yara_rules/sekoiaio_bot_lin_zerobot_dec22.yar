rule sekoiaio_bot_lin_zerobot_dec22 {
    meta:
        id = "ce028297-a526-4a6a-95db-8762fb5895f6"
        version = "1.0"
        description = "Detect the linux Zerobot implant using specific strings"
        source = "Sekoia.io"
        reference = "https://www.fortinet.com/blog/threat-research/zerobot-new-go-based-botnet-campaign-targets-multiple-vulnerabilities"
        creation_date = "2022-08-05"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "rm -rf "
        $str02 = "wget http://"
        $str03 = "curl -O http://"
        $str04 = "tftp"
        $str05 = "-c get"
        $str06 = "ftpget -v -u anonymous -P"
        $str07 = "chmod 777"
        $str08 = "nohup"
        $str09 = "/dev/null 2>&1 &"
        $str10 = "zero."
        $str11 = "ppc64le"
        $str12 = "riscv64"
        $str13 = "s390x"
        $str14 = "rm -rf ~/.bash_history"
        $str15 = "history -c"
        
    condition:
        11 of ($str*) and filesize < 10KB
}
        
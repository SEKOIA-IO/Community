rule sekoiaio_bot_lin_enemybot_april22 {
    meta:
        id = "5778c653-39ce-4f5d-b10b-1503b74e5041"
        version = "1.0"
        description = "Detect enemybot based on command line observed in strings"
        source = "Sekoia.io"
        reference = "https://twitter.com/3xp0rtblog/status/137520616938452173://www.fortinet.com/blog/threat-research/enemybot-a-look-into-keksecs-latest-ddos-botnet"
        creation_date = "2022-04-14"
        classification = "TLP:CLEAR"
        
    strings:
        $cmd0 = "wget http://%s/update.sh" ascii
        $cmd1 = "busybox wget http://%s/update.sh" ascii
        $cmd2 = "curl http://%s/update.sh" ascii
        $cmd3 = "chmod 777 update.sh" ascii
        $cmd4 = "rm -rf update.sh" ascii
        
        $str0 = "ENEMEYBOT" ascii xor
        $str1 = "KEKSEC" ascii xor
        $str2 = "/tmp/.pwned" ascii xor
        $str3 = "echo -e \"\x65\x6e\x65\x6d\x79"
        
    condition:
        (uint32(0)==0x464c457f or uint32(0)==0xfeedfacf) //elf or mach-o
        and (4 of ($cmd*) or 2 of ($str*))
}
        
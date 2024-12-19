rule bot_lin_xorddos_strings {
    meta:
        id = "2f5c70a3-fe3f-4091-905d-d779bd0cb2cd"
        version = "1.0"
        description = "Catch XORDDoS strings"
        author = "Sekoia.io"
        creation_date = "2023-11-02"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; TencentTraveler ; .NET CLR 1.1.4322)" ascii fullword
        $s2 = "sed -i '/\\/etc\\/cron.hourly\\/gcc.sh/d' /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" ascii fullword
        $s3 = "for i in `cat /proc/net/dev|grep :|awk -F: {'print $1'}`; do ifconfig $i up& done"
        
    condition:
        uint32(0)==0x464c457f and filesize > 600KB and filesize < 700KB and 3 of them
}
        
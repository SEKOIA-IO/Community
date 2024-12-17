rule sekoiaio_ransomware_win_lorenz {
    meta:
        id = "6936cc61-efe5-4d13-b76f-e808ab331457"
        version = "1.1"
        description = "Detect the Lorenz ransomware"
        author = "Sekoia.io"
        creation_date = "2022-02-10"
        classification = "TLP:CLEAR"
        reference = "https://www.cybereason.com/blog/cybereason-vs.-lorenz-ransomware"
        
    strings:
        $s1 = ".onion" ascii
        $s2 = "---===Lorenz. Welcome. Again. ===--" ascii
        $s3 = ".Lorenz.sz40" ascii
        
        $url1 = "egypghtljedbs3x3ui45tfhosakzb376epl7baq2ruzfyewcypswhgqd.onion" ascii
        $url2 = "lorenzmlwpzgxq736jzseuterytjueszsvznuibanxomlpkyxk6ksoyd.onion" ascii
        $url3 = "vsoonropylvbfqnq2urk7uhaxn7afiwgldnj3ntc743awigojm4p7lid.onion" ascii
        $url4 = "kpb3ss3vwvfejd4g3gvpvqo6ad7nnmvcqoik4mxt2376yu2adlg5fwyd.onion" ascii
        $url5 = "vldkrmiqriwlgm2wuxg42nvc6kqsdzsdhsybn27hyn34d66465fxz7id.onion" ascii
        
    condition:
        uint16(0) == 0x5a4d
        and filesize > 900KB
        and filesize < 1200KB
        and (all of ($s*) or 1 of ($url*))
}
        
rule sekoiaio_webshell_wso_webshell_strings {
    meta:
        id = "84340792-73a4-4d61-9957-6cfa1f6444a7"
        version = "1.0"
        description = "Detects the WSO webshells"
        author = "Sekoia.io"
        creation_date = "2022-04-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "decrypt($str,$pwd){$pwd=base64_encode($pwd);"
        $ = "prototype(md5($_SERVER['HTTP_HOST'])"
        $ = "$_COOKIE[md5($_SERVER['HTTP_HOST'])."
        $ = "set(a,c,p1,p2,p3,charset)"
        $ = "(($p & 0x0008) ? (($p & 0x0400)"
        $ = "gcc','lcc','cc','ld','make','php"
        
    condition:
        3 of them
}
        
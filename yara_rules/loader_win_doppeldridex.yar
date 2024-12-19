import "pe"
        
rule loader_win_doppeldridex {
    meta:
        id = "ee5111ae-ba0b-4cd3-abe6-c66324d16840"
        version = "1.1"
        description = "Detect the DoppelDridex banking trojan using its Rich header"
        author = "Sekoia.io"
        creation_date = "2021-09-28"
        classification = "TLP:CLEAR"
        
    condition:
        pe.rich_signature.toolid(122, 50727)
        and pe.rich_signature.toolid(1, 0)
        and pe.rich_signature.toolid(222, 40629)
        and pe.rich_signature.toolid(131, 30729)
        and pe.rich_signature.toolid(220, 31101)
        and pe.rich_signature.toolid(202, 60315)
        and pe.rich_signature.toolid(202, 50727)
        and pe.rich_signature.toolid(261, 23506)
        and pe.rich_signature.toolid(149, 21022)
        and pe.rich_signature.toolid(261, 23918)
        and pe.rich_signature.toolid(219, 21005)
        and pe.rich_signature.toolid(171, 30319)
        and pe.rich_signature.toolid(225, 21005)
        and pe.rich_signature.toolid(221, 21005)
        and pe.rich_signature.toolid(259, 24210)
        and pe.rich_signature.toolid(258, 24213)
        and pe.rich_signature.toolid(158, 40219)
        and pe.rich_signature.toolid(145, 21022)
        and pe.rich_signature.toolid(207, 60315)
        and pe.rich_signature.toolid(256, 23026)
}
        
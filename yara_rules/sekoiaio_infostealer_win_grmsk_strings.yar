rule sekoiaio_infostealer_win_grmsk_strings {
    meta:
        version = "1.0"
        description = "Finds GrMsk samples based on the specific strings"
        source = "Sekoia.io"
        creation_date = "2023-11-30"
        id = "58f32339-5e0f-405c-9acc-14b93f6c208b"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "ref.txt" ascii fullword
        $str02 = "--------" ascii fullword
        $str03 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/5362 (KHTML, like Gecko) Chrome/40.0.834.0 Mobile Safari/5362" ascii fullword
        $str04 = "POST" ascii fullword
        $str05 = "\\SearchWallet\\" ascii
        $str06 = "1234niwef" ascii
        $str07 = "afbcbjpbpfadlkmhmclhkeeodmamcflc" ascii
        $str08 = "lodccjjbdhfakaekdiahmedfbieldgik" ascii
        $str09 = "wallets" ascii
        $str10 = "config" ascii
        $str11 = "\"recently_open\": [" ascii
        $str12 = "\"gui_last_wallet\": " ascii
        $str13 = "YUOhtyugjKgdfgjFGghj676jj" ascii
        
    condition:
        uint16(0)==0x5A4D and 10 of ($str*)
}
        
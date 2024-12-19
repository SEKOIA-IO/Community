rule emmenhtal_strings_hta_exe {
    meta:
        id = "64e08610-e8a4-4edd-8f6b-d4e8d2b47d87"
        version = "1.0"
        description = "Emmenhtal Loader string"
        author = "Sekoia.io"
        creation_date = "2024-09-06"
        classification = "TLP:CLEAR"
        hash = "e86a22f1c73b85678e64341427c7193ba65903f3c0f29af2e65d7c56d833d912"
        
    strings:
        $char = / = String\.fromCharCode\([a-zA-Z]{2,4},[a-zA-Z]{2,4},/
        $var = "var "
        $eval = "eval("
        $script1 = "<script>"
        $script2 = "</script>MZ"
        //$hta = "<HTA:APPLICATION CAPTION = \"no\" WINDOWSTATE = \"minimize\" SHOWINTASKBAR = \"no\" >"  NOT IN ALL SAMPLES
        
    condition:
        uint16be(0) == 0x4d5a and all of them and $var in (@script1..@script1+2000) and $char in (@var..@var+100)
}
        
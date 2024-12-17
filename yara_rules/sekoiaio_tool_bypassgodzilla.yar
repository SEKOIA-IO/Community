rule sekoiaio_tool_bypassgodzilla {
    meta:
        id = "fa492f97-a46c-422d-a617-c503744ee22e"
        version = "1.0"
        description = "Detects payload of BypassGodzilla"
        author = "Sekoia.io"
        creation_date = "2024-09-09"
        classification = "TLP:CLEAR"
        hash = "571c9042c627abba19ba1d591e2083eb"
        hash = "56cfc5a876f8f55bf184be9f368b6d8a"
        hash = "d4f7ca537701aee8849c474bc4df19d1"
        hash = "e4be04331c5f447b3ca03aa637d16c85"
        hash = "905fa3b692577a086ac654ef89e8b83d"
        
    strings:
        $jsp_1a = "response.getWriter().write(\""
        $jsp_1b = "\".substring("
        $jsp_2a = "response.getWriter().write(java.util.Base64/*"
        $jsp_2b = "*/.getEncoder()/*"
        $jsp_2c = ".toByteArray(),true)));"
        
        $asp_1 = "[\"payload\"]).CreateInstance(\"LY\");"
        $asp_2 = "\\U00000045\\U00000071\\U00000075\\U00000061\\U0000006C\\U00000073(Context);"
        
        $php_1 = "=(\"!\"^\"@\").'ss'.Chr(\"101\").'rs';"
        $php_2 = "*/md5/*"
        $php_3 = "*/isset($_SESSION/*"
        $php_4 = "@set_time_limit(Chr(\"48\"))"
        
    condition:
        (
            (all of ($jsp_*) and (@jsp_1b-@jsp_1a < 70) and (@jsp_2b-@jsp_2a < 70) and (@jsp_2c - @jsp_2a < 160)) or
            (all of ($asp_*) and (@asp_2 > @asp_1)) or
            (all of ($php_*))
        ) and
        filesize < 30KB and 
        true
}
        
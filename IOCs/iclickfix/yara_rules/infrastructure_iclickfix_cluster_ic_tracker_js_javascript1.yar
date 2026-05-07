rule infrastructure_iclickfix_cluster_ic_tracker_js_javascript1 {
    meta:
        description = "Find the first obfuscated JavaScript of the IClickFix cluster, that contacts the .php?data= URL to download the second JavaScript"
        source = "Sekoia.io"
        reference = "https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/" 
        creation_date = "2025-12-04"
        modification_date = "2025-12-04"
        classification = "TLP:CLEAR"

    strings:
        $obfjs01 = "'location'" ascii
        $obfjs02 = "'style'" ascii
        $obfjs03 = "?data=" ascii
        $obfjs04 = "={'host'" ascii
        $obfjs05 = "animation:1s\\x20ease-in-out\\x201s\\x20forwards\\x20fadeIn}'," ascii
        $obfjs06 = "}(document," ascii
        $obfjs07 = "'aHR0cH" ascii
        $obfjs08 = "'now'" ascii

    condition:
        6 of ($obfjs0*)
}

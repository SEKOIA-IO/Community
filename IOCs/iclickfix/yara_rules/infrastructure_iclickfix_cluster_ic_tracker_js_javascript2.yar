rule infrastructure_iclickfix_cluster_ic_tracker_js_javascript2 {
    meta:
        description = "Find the second JavaScript of the IClickFix cluster, that contacts the .php?page= URL to download the ClickFix lure"
        source = "Sekoia.io"
        reference = "https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/" 
        creation_date = "2025-12-04"
        modification_date = "2025-12-04"
        classification = "TLP:CLEAR"

    strings:
        $datajs01 = "xhr.send();" ascii
        $datajs02 = ".php?page=\");" ascii
        $datajs03 = "function getFaviconPath() {" ascii
        $datajs04 = "close-tlc-data" ascii
        $datajs05 = ".php?click=1&data=\"" ascii
        $datajs06 = "// listen from child" ascii
        $datajs07 = "--loadNumValue" ascii
        $datajs08 = "encodeURIComponent(JSON.stringify(data))" ascii
        $datajs09 = "/* WHITE background: rgba(255,255,255,0.65); */" ascii

    condition:
        6 of ($datajs0*)
}

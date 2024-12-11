rule sekoiaio_technique_csv_dde_exec_regex {
    meta:
        id = "71d0e987-51ab-49bc-9d0d-d2f9006af1de"
        version = "1.0"
        description = "Find .csv file exploiting DDE technique"
        source = "Sekoia.io"
        creation_date = "2022-02-02"
        classification = "TLP:CLEAR"
        
    strings:
        $cmd0 = /=\s*wmic\|/ nocase
        $cmd1 = /=\s*cmd\|/ nocase
        $cmd2 = /=\s*wscript\|/ nocase
        $cmd3 = /=\s*cscript\|/ nocase
        $cmd4 = /=\s*powershell\|/ nocase
        
    condition:
        any of ($cmd*) and filesize < 20000
}
        
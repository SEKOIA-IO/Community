rule sekoiaio_apt_globalshadow {
    meta:
        id = "2fef6192-25a6-4d6a-8e19-53ad51617d90"
        version = "1.0"
        description = "Detects the GLOBALSHADOW malware"
        source = "Sekoia.io"
        creation_date = "2024-09-04"
        classification = "TLP:CLEAR"
        hash = "68c16b6f178c88c12c9555169887c321"
        
    strings:
        $command1 = "time to rest"  wide
        $command2 = "pw" wide
        $command3 = "pr" wide
        $command4 = "dnld" wide
        $step1 = "step1-" wide
        $step2 = "step2-" wide
        $step3 = "step3-" wide
        $step4 = "step4-" wide
        $step5 = "step5-" wide
        $step6 = "step6-" wide
        $delim = "]#@#[" wide
        
    condition:
        uint16be(0) == 0x4d5a and 
        2 of ($command*) and 3 of ($step*) and $delim and
        true
}
        
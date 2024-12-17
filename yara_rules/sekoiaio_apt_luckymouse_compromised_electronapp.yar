rule sekoiaio_apt_luckymouse_compromised_electronapp {
    meta:
        id = "7702217d-771f-47af-8eaa-d5acf1e14f4d"
        version = "1.0"
        description = "Detects compromised ElectronApp"
        author = "Sekoia.io"
        creation_date = "2022-08-05"
        classification = "TLP:CLEAR"
        
    strings:
        $s = "module.exports=function(t){eval(function(p,a,c,k,e,r)"
        
    condition:
        $s at 0 and filesize < 100KB
}
        
rule sekoiaio_spyware_and_bahamut {
    meta:
        id = "d416997e-baf1-412c-bf39-905a6e19b65e"
        version = "1.0"
        description = "Detect Bahamut's spyware based on common information gathering function names"
        author = "Sekoia.io"
        creation_date = "2022-11-23"
        classification = "TLP:CLEAR"
        reference = "https://www.welivesecurity.com/2022/11/23/bahamut-cybermercenary-group-targets-android-users-fake-vpn-apps/"
        hash1 = "c51dc2132c830c560aaeae4bf48e5f0d28c84b36d27840b5c2ba170d87f4afa5"
        hash2 = "d7e2cf642b236dba9ba0cbe5a9dc28baf22477973d5ce163e21ec40f5f26e078"
        
    strings:
        $ = "FbDao"
        $ = "SignalDao"
        $ = "conionDao"
        
    condition:
        all of them
}
        
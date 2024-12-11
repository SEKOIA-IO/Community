rule sekoiaio_downloader_kimsuky_lnk {
    meta:
        id = "3831d115-7874-4bc9-aeb4-d2cb9bc2b5c9"
        version = "1.0"
        description = "Detect Kimsuky LNK"
        source = "Sekoia.io"
        creation_date = "2024-07-16"
        classification = "TLP:CLEAR"
        reference = "https://blogs.jpcert.or.jp/en/2024/07/attack-activities-by-kimsuky-targeting-japanese-organizations.html"
        hash1 = "3065b8e4bb91b4229d1cea671e8959da8be2e7482067e1dd03519c882738045e"
        hash2 = "d912f49d24792aa7197509f76e2097ac3858cde23199e1b40f2516948d39c589"
        hash3 = "e936445935c4a636614f7113e4121695a5f3e4a6c137b7cdcceb6f629aa957c4"
        hash4 = "fe156159a26f8b7c140db61dd8b136e1c8103a800748fe9b70a3a3fdf179d3c3"
        
    strings:
        $ = "AType: Text Document" wide
        $ = "Size: 5.23 KB" wide
        $ = "Date modified: 01/02/2020 11:23" wide
        
    condition:
        all of them
}
        
rule sekoiaio_tool_sharphoundexecutable_strings {
    meta:
        id = "2cf8046e-5b4d-4ff7-b4b2-7aaeaf58883b"
        version = "1.0"
        description = "Detects the SharpHound tool"
        author = "Sekoia.io"
        creation_date = "2022-08-11"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "BloodHoundLoopResults.zip" wide
        $ = "[-] Removed PSRemote Collection" wide
        $ = "Initializing SharpHound at {time} on {date}" wide
        $ = "[SearchForest] Cross-domain enumeration may result in reduced data quality" wide
        $ = "SharpHound Enumeration Completed at {Time} on {Date}! Happy Graphing!" wide
        $ = "Consumer task on thread {id} completed" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        3 of them
}
        
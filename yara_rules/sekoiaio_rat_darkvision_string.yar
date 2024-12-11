rule sekoiaio_rat_darkvision_string {
    meta:
        id = "ab698a79-42ee-452a-a3ba-1a9872d5e2bc"
        version = "1.0"
        description = "DarkVision RAT based on string"
        source = "Sekoia.io"
        creation_date = "2024-09-17"
        classification = "TLP:CLEAR"
        hash = "8ec5526cecc596e0711c82e39cd4f2ce"
        hash = "2dd476464e46d91ffe68483cb478d9b4"
        hash = "20de7547d79d3637430b6a0787e59df5"
        hash = "60d1e02316e6f22e078f9aa710790912"
        hash = "e136e51efc22b0e071c11e7d652ea3be"
        hash = "f466be81310147fcdd9a7886735a3786"
        hash = "5065134cf4ba765bd97bb2edb61c5869"
        hash = "6ed21c4f507e8cc830141ff732bd5acc"
        hash = "40b2641150f291ca07bd08ab629fe1ed"
        hash = "3f20cd14137e0abfa84b39e29a277350"
        hash = "7dc8427be8b4d26a49fd380ad40d3b96"
        
    strings:
        $ = "DarkVision Installation" wide
        $ = "You are about to install DarkVision Remote Access Tool." wide
        
    condition:
        uint16be(0) == 0x4d5a and
        2 of them
}
        
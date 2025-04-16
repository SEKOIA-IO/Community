rule backdoor_win_interlock_powershell_backdoor {
	meta:
    	id = "678827c2-9416-417b-98c3-6e22010bb541"
    	version = "1.0"
    	malware = "Interlock RAT"
    	description = "Detect the Interlock PowerShell backdoor"
    	source = "Sekoia.io"
    	creation_date = "2025-03-24"
    	classification = "TLP:GREEN"

	strings:
    	$ = "path: '/init1234'" nocase
    	$ = "Get-PSDrive -PSProvider FileSystem" nocase
    	$ = "[security.principal.windowsidentity]::getcurrent().name" nocase

	condition:
    	all of them
}

import "pe"

rule crypter_win_InterLock_resources {
	meta:
    	id = "9b9fdb90-4227-4bd1-a7a8-6b4cef71ee44"
    	version = "1.0"
    	malware = "InterLock"
    	intrusion_set = "Interlock ransomware operators"
    	description = "Detect resources used in every files tied to InterLock malware"
    	source = "Sekoia.io"
    	creation_date = "2024-11-14"
    	classification = "TLP:GREEN"

	condition:
    	for any i in (0..pe.number_of_resources-1) : (
        	hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "0e0a647b3156d430cd70ad5a430277dc99014d069940a64d9db1ecd60ca00467"
        	or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "58ed0431455a1d354369206a1197d1acfcd3e0946cdc733bee50573867fda444"
    	)
}

rule Interlock_ClickFix_PowerShell_loader {
	meta:
    	id = "78e02729-d926-4600-affc-6e249e90ce19"
    	version = "1.0"
    	intrusion_set = "Interlock"
    	description = "Detect the PowerShell loader used by Interlock operators to execute the PowerShell backdoor using the ClickFix technique"
    	source = "Sekoia.io"
    	creation_date = "2025-03-31"
    	classification = "TLP:GREEN"

	strings:
    	// "}.Items(), 4 + 16)"
    	$ = {7D 2E 49 74 65 6D 73 28 29 2C 20 34 20 2B 20 31 36 29}
	    $ = "} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("

	condition:
    	all of them
}

rule crypter_win_interlock_keywords_nov24 {
	meta:
		id = "ae3905ee-046b-415e-b83c-9e5d07d6b443"
		version = "1.0"
        intrusion_set = "Interlock ransomware operators"
		description = "Finds crypter used by Interlock and Rhysida intrusion sets"
		source = "Sekoia"
		creation_date = "2024-11-18"
		hash = "1f568c2eaa8325bf7afcf7a90f9595f8b601a085769a44c4ffa1cdfdd283594c"
		hash = "8e273e1e65b337ad8d3b2dec6264ed90d1d0662bd04d92cbd02943a7e12df95a"

	strings:
		$wrd01 = "ceremoniously" ascii
		$wrd02 = "biophysicist" ascii
		$wrd03 = "cyberpunks" ascii
		$wrd04 = "undercarriages" ascii
		$wrd05 = "abomination" ascii
		$wrd06 = "greediness" ascii
		$wrd07 = "Heaviside" ascii
		$wrd08 = "misapprehending" ascii
		$wrd09 = "magnetosphere" ascii
		$wrd10 = "distinctively" ascii
		$wrd11 = "stringently" ascii
		$wrd12 = "sentimentalist" ascii
		$wrd13 = "hydrocarbons" ascii
		$wrd14 = "discontinuations" ascii
		$wrd15 = "woodcutter" ascii
		$wrd16 = "preoccupation" ascii
		$wrd17 = "pocketful" ascii
		$wrd18 = "Polynesian" ascii
		$wrd19 = "laundrymen" ascii
		$wrd20 = "hyprocri" ascii
		$wrd21 = "interlocking" ascii
		$wrd22 = "blackballing" ascii
		$wrd23 = "selectivity" ascii
		$wrd24 = "incontrovertible" ascii
		$wrd25 = "mutinously" ascii

		$hea01 = "<supportedOS Id=\"{" ascii

	condition:
		uint16(0)==0x5A4D
		and 5 of ($wrd*)
		and #hea01 > 4
		and vt.metadata.new_file
        and filesize < 2MB
}
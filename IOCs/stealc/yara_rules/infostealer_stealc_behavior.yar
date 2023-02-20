import "vt"

rule infostealer_win_stealc_behaviour {
	meta:
		malware = "Stealc"
		description = "Find Stealc sample based characteristic behaviors"
		source = "SEKOIA.IO"
		reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity---part-1/"
		classification = "TLP:CLEAR"

	condition:
        for any cmd in vt.behaviour.command_executions : (
        	cmd contains "\\*.dll"
        ) and
        for any cmd in vt.behaviour.command_executions : (
        	cmd contains "/c timeout /t 5 & del /f /q"
        ) and
		for any c in vt.behaviour.http_conversations : (
			c.url contains ".php"
		)
}

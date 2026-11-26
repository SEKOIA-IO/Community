# Community

Welcome to the Sekoia Community repository! This repository contains IOCs, cyber threat intelligence materials, hunting queries, detection rules, 
playbooks and much more to help you make the most of the capabilities of Sekoia Autonomous SOC platform.

For questions and feedback, please contact support@sekoia.io 

## Playbook template

You can add playbook template in the folder: "playbooks/templates".
Your template must NOT contain the fields:
    "trigger_configuration_uuid"
    "module_configuration_uuid"
    "community_uuid"
Your need to add your new template file to the list of template in the file: 
    "playbooks/templates/playbooks.json"
